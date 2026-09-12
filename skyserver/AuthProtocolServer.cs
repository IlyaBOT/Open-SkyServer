using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SkyServer
{
    internal sealed class AuthProtocolServer
    {
        private const int SuccessPayloadLength = 285;
        private const int FailurePayloadLength = 14;

        private readonly SkyDatabase database;
        private readonly IPAddress bindAddress;
        private readonly int port;
        private readonly bool once;
        private readonly bool realSkypeProbe;
        private readonly CommunityKeys communityKeys;
        private readonly object clientsLock = new object();
        private readonly HashSet<TcpClient> activeClients = new HashSet<TcpClient>();
        private TcpListener listener;
        private volatile bool stopped;
        internal const int MaximumClients = 32;

        public AuthProtocolServer(SkyDatabase database, IPAddress bindAddress, int port, bool once, bool realSkypeProbe)
            : this(database, bindAddress, port, once, realSkypeProbe, null)
        {
        }

        public AuthProtocolServer(SkyDatabase database, IPAddress bindAddress, int port, bool once, bool realSkypeProbe, CommunityKeys communityKeys)
        {
            this.database = database;
            this.bindAddress = bindAddress;
            this.port = port;
            this.once = once;
            this.realSkypeProbe = realSkypeProbe;
            this.communityKeys = communityKeys;
        }

        public void Run()
        {
            lock (clientsLock)
            {
                if (stopped) return;
                listener = new TcpListener(bindAddress, port);
                listener.Start();
            }
            Console.WriteLine("auth listening on {0}:{1}", bindAddress, port);
            try
            {
                do
                {
                    TcpClient client = listener.AcceptTcpClient();
                    lock (clientsLock)
                    {
                        if (stopped || activeClients.Count >= MaximumClients)
                        {
                            client.Close();
                            continue;
                        }
                        activeClients.Add(client);
                    }
                    if (once) HandleAcceptedClient(client);
                    else if (!ThreadPool.QueueUserWorkItem(HandleAcceptedClient, client)) ReleaseClient(client);
                }
                while (!once && !stopped);
            }
            catch (SocketException) { if (!stopped) throw; }
            catch (ObjectDisposedException) { if (!stopped) throw; }
            finally { Stop(); }
        }

        internal IPEndPoint ListeningEndpoint
        {
            get { lock (clientsLock) return listener == null || stopped ? null : (IPEndPoint)listener.LocalEndpoint; }
        }

        public void Stop()
        {
            lock (clientsLock)
            {
                stopped = true;
                if (listener != null) listener.Stop();
                foreach (TcpClient client in activeClients) client.Close();
            }
        }

        private void HandleAcceptedClient(object state)
        {
            TcpClient client = (TcpClient)state;
            try
            {
                Console.WriteLine("auth client {0}", client.Client.RemoteEndPoint);
                HandleClient(client);
            }
            catch (Exception ex)
            {
                if (!stopped) Console.WriteLine("auth session failed: {0}", ex.Message);
            }
            finally { ReleaseClient(client); }
        }

        private void ReleaseClient(TcpClient client)
        {
            client.Close();
            lock (clientsLock) activeClients.Remove(client);
        }

        private void HandleClient(TcpClient client)
        {
            client.ReceiveTimeout = 10000;
            client.SendTimeout = 10000;

            NetworkStream stream = client.GetStream();

            byte[] clientHello = ReadSome(stream, SkypeDh384Session.PublicKeyBytes, 1024);
            LogAuthPacket("auth dh-client-hello", client, clientHello, clientHello.Length);
            if (clientHello.Length < SkypeDh384Session.PublicKeyBytes)
            {
                Console.WriteLine(
                    "short TCP probe from {0}: {1} bytes{2}",
                    client.Client.RemoteEndPoint,
                    clientHello.Length,
                    clientHello.Length > 0 ? ", data " + Hex(clientHello, 0, clientHello.Length) : "");
                return;
            }

            SkypeDh384Session dh = new SkypeDh384Session(clientHello, clientHello.Length);
            byte[] serverHello = dh.ServerHello;
            stream.Write(serverHello, 0, serverHello.Length);
            LogAuthPacket("auth dh-server-hello", client, serverHello, serverHello.Length);

            byte[] clientHash = ReadExact(stream, 8);
            Console.WriteLine("client DH hash: {0}", Hex(clientHash));
            Console.WriteLine("expected hash:  {0}", Hex(dh.ExpectedClientHash));
            if (!dh.VerifyClientHash(clientHash, clientHash.Length))
            {
                Console.WriteLine("auth DH hash mismatch; closing session");
                return;
            }

            if (!realSkypeProbe)
            {
                HandleDirectAuthFrames(stream, dh.SharedSecret, null);
                return;
            }

            byte[] firstEncrypted;
            if (TryReadRaw(stream, 500, 4096, out firstEncrypted))
            {
                LogAuthPacket("auth post-dh-first", client, firstEncrypted, firstEncrypted.Length);
                if (LooksLikeDirectRc4Login(dh.SharedSecret, firstEncrypted))
                {
                    Console.WriteLine("auth transport selected: reconstructed direct RC4");
                    HandleDirectAuthFrames(stream, dh.SharedSecret, firstEncrypted);
                    return;
                }

                Console.WriteLine("auth post-dh data did not match direct RC4 login; cannot safely switch to stock server-first flow after consuming it");
                return;
            }

            Console.WriteLine("auth transport selected: stock Skype DH384 ack + direct RC4 login");
            HandleStockSkypeAuthFrames(stream, client, dh);
        }

        private void HandleDirectAuthFrames(NetworkStream stream, byte[] sharedSecretBytes, byte[] firstEncryptedChunk)
        {
            Rc4 inbound = Rc4.FromKey(sharedSecretBytes);
            Rc4 outbound = Rc4.FromKey(IncrementFirstByte(sharedSecretBytes));

            List<byte[]> frames = ReadDecryptedFrames(stream, inbound, 3, firstEncryptedChunk);
            Console.WriteLine("login frame 1: {0} bytes, header {1}", frames[0].Length, Hex(frames[0], 0, Math.Min(5, frames[0].Length)));
            Console.WriteLine("login frame 2: {0} bytes, header {1}", frames[1].Length, Hex(frames[1], 0, Math.Min(5, frames[1].Length)));

            Console.WriteLine("local auth frame: {0} bytes, header {1}", frames[2].Length, Hex(frames[2], 0, Math.Min(5, frames[2].Length)));
            LocalAuthRequest auth = ParseLocalAuthFrame(frames[2]);
            bool valid = database.ValidatePassword(auth.Username, auth.Password);
            if (valid)
            {
                database.CreateSession(auth.Username);
                Console.WriteLine("auth ok for {0}", auth.Username);
            }
            else
            {
                Console.WriteLine("auth rejected for {0}", auth.Username);
            }

            byte[] response = BuildReconstructedAuthResponse(valid ? SuccessPayloadLength : FailurePayloadLength);
            outbound.Crypt(response, 0, response.Length);
            stream.Write(response, 0, response.Length);
            Console.WriteLine("sent auth {0} frame", valid ? "success" : "failure");
        }

        internal void HandleStockSkypeAuthFrames(NetworkStream stream, TcpClient client, SkypeDh384Session dh,
            byte[] firstEncrypted = null, bool ackAlreadySent = false)
        {
            byte[] serverHash = dh.ServerHash;
            if (!ackAlreadySent)
            {
                stream.Write(serverHash, 0, serverHash.Length);
                LogAuthPacket("auth dh-server-ack", client, serverHash, serverHash.Length);
            }

            Rc4 inbound = Rc4.FromKey(dh.SharedSecret);
            List<byte[]> frames = ReadDecryptedFrames(stream, inbound, 2, firstEncrypted);
            for (int i = 0; i < frames.Count; i++)
            {
                Console.WriteLine(
                    "auth stock login frame {0}: {1} bytes, header {2}",
                    i + 1,
                    frames[i].Length,
                    Hex(frames[i], 0, Math.Min(5, frames[i].Length)));
            }

            if (frames[0][0] != 0x16 || frames[1][0] != 0x17 ||
                frames[0].Length <= 5 || frames[1].Length <= 7)
            {
                throw new InvalidDataException("unexpected stock Skype login frame sequence");
            }

            if (communityKeys == null)
            {
                Console.WriteLine("auth stock: no community private keys configured; use --keys-dir after client trust patching");
                Console.WriteLine("auth stock unauthenticated: no DB password validation or session creation; closing without a fabricated success response");
                return;
            }
            using (NativeLoginRequest request = NativeLoginRequest.Parse(frames[0], frames[1], communityKeys))
            {
                bool valid = database.ValidateNativePasswordHash(request.Username, request.PasswordDigest);
                Console.WriteLine("auth stock native password verification: {0}", valid ? "valid" : "rejected or not provisioned");
                if (!valid) return;
                byte[] payload;
                if (request.Operation == 0x139c)
                    payload = NativeCredentials.EmailPayload(database.GetAccountEmail(request.Username), request.RequestId);
                else
                {
                    byte[] credential = NativeCredentials.Issue(communityKeys, request.Username, request.ClientPublicKey, DateTime.UtcNow);
                    payload = NativeCredentials.SuccessPayload(credential, request.RequestId);
                }
                byte[] response = NativeCredentials.ProtectResponse(payload, request.AesKey);
                Rc4 outbound = Rc4.FromKey(IncrementFirstByte(dh.SharedSecret));
                outbound.Crypt(response, 0, response.Length);
                stream.Write(response, 0, response.Length);
                Console.WriteLine("auth stock: operation 0x{0:X} {1} response sent ({2} bytes); native login/contacts UI is not confirmed.",
                    request.Operation, request.Operation == 0x139c ? "DB account email" : "community-signed credential", response.Length);
            }
        }

        internal static bool IsAccountRecordPrefix(byte[] secret, byte[] encrypted)
        {
            if (encrypted == null || encrypted.Length < 5) return false;
            byte[] prefix = (byte[])encrypted.Clone();
            Rc4.FromKey(secret).Crypt(prefix, 0, prefix.Length);
            return prefix[0] == 0x16 && prefix[1] == 3 && prefix[2] == 1 &&
                ((prefix[3] << 8) | prefix[4]) >= 192 && ((prefix[3] << 8) | prefix[4]) <= 16384;
        }

        private static LocalAuthRequest ParseLocalAuthFrame(byte[] frame)
        {
            if (frame.Length < 5 || frame[0] != 0x18)
            {
                throw new InvalidDataException("missing local auth frame");
            }

            int length = (frame[3] << 8) | frame[4];
            if (length != frame.Length - 5)
            {
                throw new InvalidDataException("invalid local auth frame length");
            }

            string payload = Encoding.ASCII.GetString(frame, 5, length);
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] lines = payload.Replace("\r", "").Split('\n');
            if (lines.Length == 0 || lines[0] != "SKYSERVER-AUTH/1")
            {
                throw new InvalidDataException("invalid local auth marker");
            }

            for (int i = 1; i < lines.Length; i++)
            {
                int p = lines[i].IndexOf('=');
                if (p > 0)
                {
                    values[lines[i].Substring(0, p)] = lines[i].Substring(p + 1);
                }
            }

            if (!values.ContainsKey("user_hex") || !values.ContainsKey("pass_hex"))
            {
                throw new InvalidDataException("local auth frame has no credentials");
            }

            return new LocalAuthRequest
            {
                Username = DecodeHexString(values["user_hex"]),
                Password = DecodeHexString(values["pass_hex"])
            };
        }

        private static List<byte[]> ReadDecryptedFrames(NetworkStream stream, Rc4 rc4, int expectedFrames)
        {
            return ReadDecryptedFrames(stream, rc4, expectedFrames, null);
        }

        private static List<byte[]> ReadDecryptedFrames(NetworkStream stream, Rc4 rc4, int expectedFrames, byte[] firstEncryptedChunk)
        {
            List<byte> decrypted = new List<byte>();
            List<byte[]> frames = new List<byte[]>();
            byte[] encryptedBuffer = new byte[4096];
            int offset = 0;

            if (firstEncryptedChunk != null && firstEncryptedChunk.Length > 0)
            {
                byte[] chunk = new byte[firstEncryptedChunk.Length];
                Buffer.BlockCopy(firstEncryptedChunk, 0, chunk, 0, firstEncryptedChunk.Length);
                rc4.Crypt(chunk, 0, chunk.Length);
                decrypted.AddRange(chunk);
                ExtractTlsFrames(decrypted, ref offset, frames, expectedFrames);
            }

            while (frames.Count < expectedFrames)
            {
                int read = stream.Read(encryptedBuffer, 0, encryptedBuffer.Length);
                if (read <= 0)
                {
                    throw new EndOfStreamException("socket closed while reading login frames");
                }

                byte[] chunk = new byte[read];
                Buffer.BlockCopy(encryptedBuffer, 0, chunk, 0, read);
                rc4.Crypt(chunk, 0, chunk.Length);
                decrypted.AddRange(chunk);

                ExtractTlsFrames(decrypted, ref offset, frames, expectedFrames);
            }

            return frames;
        }

        private static List<byte[]> ReadNativeDecryptedFrames(NetworkStream stream, TcpClient client, SkypeNativeRc4.Session rc4, byte[] firstClearChunk, int expectedFrames)
        {
            List<byte> decrypted = new List<byte>();
            List<byte[]> frames = new List<byte[]>();
            int offset = 0;

            if (firstClearChunk != null && firstClearChunk.Length > 0)
            {
                decrypted.AddRange(firstClearChunk);
                ExtractTlsFrames(decrypted, ref offset, frames, expectedFrames);
            }

            while (frames.Count < expectedFrames)
            {
                byte[] encrypted;
                if (!TryReadRaw(stream, 10000, 4096, out encrypted))
                {
                    throw new IOException("socket timed out while reading native login frames");
                }

                LogAuthPacket("auth native-client-data", client, encrypted, encrypted.Length);

                byte[] clear;
                string error;
                if (!rc4.TryDecryptFromClient(encrypted, encrypted.Length, out clear, out error))
                {
                    throw new InvalidDataException("native RC4 decrypt failed: " + error);
                }

                LogAuthPacket("auth native-client-data-clear", client, clear, clear.Length);
                decrypted.AddRange(clear);
                ExtractTlsFrames(decrypted, ref offset, frames, expectedFrames);
            }

            return frames;
        }

        private static void ExtractTlsFrames(List<byte> decrypted, ref int offset, List<byte[]> frames, int expectedFrames)
        {
            while (decrypted.Count - offset >= 5 && frames.Count < expectedFrames)
            {
                int tlsLength = (decrypted[offset + 3] << 8) | decrypted[offset + 4];
                int frameLength = 5 + tlsLength;
                if (!LooksLikeLoginFrameHeader(decrypted, offset, decrypted.Count - offset) || frameLength > 65535)
                {
                    throw new InvalidDataException("invalid login frame length/header");
                }

                if (decrypted.Count - offset < frameLength)
                {
                    break;
                }

                byte[] frame = decrypted.GetRange(offset, frameLength).ToArray();
                frames.Add(frame);
                offset += frameLength;
            }
        }

        private static bool LooksLikeDirectRc4Login(byte[] sharedSecretBytes, byte[] encrypted)
        {
            if (encrypted == null || encrypted.Length == 0)
            {
                return false;
            }

            byte[] clear = new byte[encrypted.Length];
            Buffer.BlockCopy(encrypted, 0, clear, 0, encrypted.Length);
            Rc4 preview = Rc4.FromKey(sharedSecretBytes);
            preview.Crypt(clear, 0, clear.Length);
            // TCP may split the first record header across multiple reads.
            byte[] prefix = { 0x16, 0x03, 0x01 };
            for (int i = 0; i < Math.Min(prefix.Length, clear.Length); i++)
            {
                if (clear[i] != prefix[i])
                {
                    return false;
                }
            }
            return true;
        }

        private static bool LooksLikeLoginFrameHeader(List<byte> data, int offset, int available)
        {
            if (available < 5)
            {
                return false;
            }

            byte contentType = data[offset];
            if (contentType != 0x16 && contentType != 0x17 && contentType != 0x18)
            {
                return false;
            }

            return data[offset + 1] == 0x03 && data[offset + 2] == 0x01;
        }

        private static bool LooksLikeLoginFrameHeader(byte[] data, int offset, int available)
        {
            if (data == null || available < 5)
            {
                return false;
            }

            byte contentType = data[offset];
            if (contentType != 0x16 && contentType != 0x17 && contentType != 0x18)
            {
                return false;
            }

            return data[offset + 1] == 0x03 && data[offset + 2] == 0x01;
        }

        private static byte[] ExtractTrailingAfterSkypeHandshake(byte[] packet)
        {
            if (packet == null || packet.Length < 17 || packet[15] != 0x03)
            {
                return new byte[0];
            }

            int garbageLengthCode = packet[14];
            if ((garbageLengthCode & 1) == 0 || garbageLengthCode < 3)
            {
                return new byte[0];
            }

            int garbageLength = (garbageLengthCode - 3) / 2;
            int consumed = 16 + garbageLength;
            if (consumed >= packet.Length)
            {
                return new byte[0];
            }

            byte[] trailing = new byte[packet.Length - consumed];
            Buffer.BlockCopy(packet, consumed, trailing, 0, trailing.Length);
            return trailing;
        }

        // This compatibility response is only understood by the reconstructed DLL.
        // It is not a native Skype credential or an AES-encrypted login response.
        private static byte[] BuildReconstructedAuthResponse(int payloadLength)
        {
            byte[] payload = new byte[payloadLength];
            for (int i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)((i * 37 + 0x41) & 0xFF);
            }

            int tlsLength = payloadLength + 2;
            byte[] packet = new byte[5 + tlsLength];
            packet[0] = 0x17;
            packet[1] = 0x03;
            packet[2] = 0x01;
            packet[3] = (byte)(tlsLength >> 8);
            packet[4] = (byte)tlsLength;
            Buffer.BlockCopy(payload, 0, packet, 5, payload.Length);

            uint crc = Crc8(payload, 0, payload.Length);
            packet[5 + payload.Length] = (byte)(crc & 0xFF);
            packet[6 + payload.Length] = (byte)((crc >> 8) & 0xFF);
            return packet;
        }

        private static byte[] ReadSome(NetworkStream stream, int minimumBytes, int maximumBytes)
        {
            byte[] result = new byte[maximumBytes];
            int total = 0;
            while (total < minimumBytes)
            {
                int read = stream.Read(result, total, maximumBytes - total);
                if (read <= 0)
                {
                    break;
                }

                total += read;
                if (stream.DataAvailable)
                {
                    continue;
                }

                if (total >= minimumBytes)
                {
                    break;
                }
            }

            byte[] trimmed = new byte[total];
            Buffer.BlockCopy(result, 0, trimmed, 0, total);
            return trimmed;
        }

        private static byte[] ReadExact(NetworkStream stream, int count)
        {
            byte[] result = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(result, offset, count - offset);
                if (read <= 0)
                {
                    throw new EndOfStreamException("socket closed");
                }

                offset += read;
            }

            return result;
        }

        private static bool TryReadRaw(NetworkStream stream, int timeoutMs, int maximumBytes, out byte[] data)
        {
            data = null;
            int oldTimeout = stream.ReadTimeout;
            stream.ReadTimeout = timeoutMs;
            try
            {
                byte[] buffer = new byte[maximumBytes];
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read <= 0)
                {
                    return false;
                }

                data = new byte[read];
                Buffer.BlockCopy(buffer, 0, data, 0, read);
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (SocketException)
            {
                return false;
            }
            finally
            {
                stream.ReadTimeout = oldTimeout;
            }
        }

        private static void LogAuthPacket(string prefix, TcpClient client, byte[] buffer, int read)
        {
            IPEndPoint local = (IPEndPoint)client.Client.LocalEndPoint;
            IPEndPoint remote = (IPEndPoint)client.Client.RemoteEndPoint;
            string details = read > 0
                ? String.Format(", data {0}, ascii {1}", Hex(buffer, 0, Math.Min(read, 64)), AsciiPreview(buffer, 0, Math.Min(read, 64)))
                : "";
            Console.WriteLine("{0} {1} -> {2}:{3} bytes: {4}{5}", prefix, remote, local.Address, local.Port, read, details);
        }

        private static byte[] IncrementFirstByte(byte[] source)
        {
            byte[] result = new byte[source.Length];
            Buffer.BlockCopy(source, 0, result, 0, source.Length);
            result[0] = (byte)(result[0] + 1);
            return result;
        }

        private static uint Crc8(byte[] data, int offset, int count)
        {
            uint z = 0xFFFFFFFF;
            for (int i = 0; i < count; i++)
            {
                z ^= data[offset + i];
                for (int j = 0; j < 8; j++)
                {
                    z = ((z & 1) != 0) ? ((z >> 1) ^ 0xEDB88320) : (z >> 1);
                }
            }

            return z;
        }

        private static string DecodeHexString(string hex)
        {
            if ((hex.Length % 2) != 0)
            {
                throw new InvalidDataException("odd hex string");
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return Encoding.UTF8.GetString(bytes);
        }

        private static string Hex(byte[] bytes)
        {
            return Hex(bytes, 0, bytes.Length);
        }

        private static string Hex(byte[] bytes, int offset, int count)
        {
            char[] chars = new char[count * 3];
            int p = 0;
            for (int i = 0; i < count; i++)
            {
                byte b = bytes[offset + i];
                chars[p++] = GetHex((b >> 4) & 0xF);
                chars[p++] = GetHex(b & 0xF);
                chars[p++] = ' ';
            }

            return new string(chars).TrimEnd();
        }

        private static string AsciiPreview(byte[] bytes, int offset, int count)
        {
            StringBuilder builder = new StringBuilder(count);
            for (int i = 0; i < count; i++)
            {
                byte b = bytes[offset + i];
                builder.Append(b >= 0x20 && b <= 0x7E ? (char)b : '.');
            }

            return builder.ToString();
        }

        private static char GetHex(int value)
        {
            return (char)(value < 10 ? '0' + value : 'A' + value - 10);
        }

        private sealed class LocalAuthRequest
        {
            public string Username;
            public string Password;
        }

        private sealed class Rc4
        {
            private readonly byte[] s;
            private int i;
            private int j;

            private Rc4(byte[] state)
            {
                s = state;
            }

            public static Rc4 FromKey(byte[] key)
            {
                byte[] state = new byte[256];
                for (int n = 0; n < state.Length; n++)
                {
                    state[n] = (byte)n;
                }

                int j = 0;
                int keyOffset = 0;
                for (int n = 0; n < state.Length; n++)
                {
                    int t = state[n];
                    j = (t + key[keyOffset++] + j) & 0xFF;
                    state[n] = state[j];
                    state[j] = (byte)t;
                    if (keyOffset >= key.Length)
                    {
                        keyOffset = 0;
                    }
                }

                return new Rc4(state);
            }

            public void Crypt(byte[] buffer, int offset, int count)
            {
                for (int n = 0; n < count; n++)
                {
                    i = (i + 1) & 0xFF;
                    int t = s[i];
                    j = (j + t) & 0xFF;
                    s[i] = s[j];
                    s[j] = (byte)t;
                    int k = s[(s[i] + t) & 0xFF];
                    buffer[offset + n] ^= (byte)k;
                }
            }
        }
    }
}
