using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SkyServer
{
    internal sealed class TcpProbeServer
    {
        private static readonly byte[] FallbackCryptoHelloResponse = FromHex(
            "F1 74 AF E7 9F 15 E8 70 73 2B A7 A7 B8 3D 6C 60 " +
            "EB 11 50 D5 C2 BF 84 C2 A8 F5 91 A6 33 E6 69 A7 " +
            "A0 4B D0 64 A9 ED 91 97 DE F1 D2 63 B7 12 8A C8 " +
            "01 3E 17");

        private static readonly byte[] FallbackCryptoAckResponse = FromHex(
            "BE FB B0 FD A0 AC 1A 0D");

        private static readonly byte[] FallbackSslServerHelloResponse = FromHex(
            "16 03 01 00 4A 02 00 00 46 03 01 40 1B E4 86 02 " +
            "AD E0 29 E1 77 74 E5 44 B9 C9 9C B4 31 31 5E 02 " +
            "DD 77 9D 15 4A 96 09 BA 5D A8 70 20 1C A0 E4 F6 " +
            "4C 63 51 AE 2F 8E 4E E1 E6 76 6A 0A 88 D5 D8 C5 " +
            "5C AE 98 C5 E4 81 F2 2A 69 BF 90 58 00 05 00");

        private static readonly byte[] FallbackCryptoConnectedResponse = FromHex(
            "9C B7 18 A1 BC 96 47 8D 2C 0D 85 B4 49 0F DF CB " +
            "BB B0 66 BF 4D 2D BF 61 6E B3 F0 C9 7B 2C 36 6D " +
            "BF 9D 51 4A 23 5E FB 92 7D 4B 73 80 84 66 7C B6 " +
            "DB 62 B4 05 CE 81 45 73 C6 CE 73 11 2C A2 A4 F5 " +
            "DA FB");

        private static readonly byte[] SupernodeProbePayload = FromHex(
            "42 6A C5 8D 1E BC 40 53 BB CD");

        private static int nextServerSequence = Environment.TickCount;

        private readonly IPAddress bindAddress;
        private readonly int[] ports;
        private readonly AuthProtocolServer accountServer;
        private readonly NativeRecordDirectory recordDirectory;
        private readonly List<TcpListener> listeners = new List<TcpListener>();
        private volatile bool stopped;

        private readonly NetworkAccessPolicy access;
        private readonly IPAddress advertisedAddress;
        private readonly Semaphore connectionSlots = new Semaphore(128, 128);
        public TcpProbeServer(IPAddress bindAddress, int[] ports, AuthProtocolServer accountServer = null, CommunityKeys keys = null, NetworkAccessPolicy access = null, IPAddress advertisedAddress = null)
        {
            this.access = access ?? NetworkAccessPolicy.Open;
            this.advertisedAddress = advertisedAddress;
            this.bindAddress = bindAddress;
            this.ports = ports;
            this.accountServer = accountServer;
            this.recordDirectory = new NativeRecordDirectory(keys);
        }

        public void Run()
        {
            for (int i = 0; i < ports.Length; i++)
            {
                TcpListener listener = new TcpListener(bindAddress, ports[i]);
                try
                {
                    listener.Start();
                    listeners.Add(listener);

                    Thread thread = new Thread(AcceptLoop);
                    thread.IsBackground = true;
                    thread.Start(listener);
                    Console.WriteLine("tcp probe listening on {0}:{1}", bindAddress, ports[i]);
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("tcp probe could not bind {0}:{1}: {2}", bindAddress, ports[i], ex.Message);
                }
            }

            while (!stopped)
            {
                Thread.Sleep(250);
            }
        }

        public void Stop()
        {
            stopped = true;
            foreach (TcpListener listener in listeners)
            {
                listener.Stop();
            }
        }

        private void AcceptLoop(object state)
        {
            TcpListener listener = (TcpListener)state;
            while (!stopped)
            {
                try
                {
                    TcpClient client = listener.AcceptTcpClient();
                    if (!access.Accept(client)) continue;
                    if (!connectionSlots.WaitOne(0)) { client.Close(); continue; }
                    ThreadPool.QueueUserWorkItem(delegate(object item) {
                        try { HandleClient(item); }
                        finally { connectionSlots.Release(); }
                    }, client);
                }
                catch (SocketException)
                {
                    if (!stopped)
                    {
                        throw;
                    }
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
            }
        }

        private void HandleClient(object state)
        {
            using (TcpClient client = (TcpClient)state)
            {
                client.ReceiveTimeout = 10000;
                client.SendTimeout = 10000;

                IPEndPoint local = (IPEndPoint)client.Client.LocalEndPoint;
                IPEndPoint remote = (IPEndPoint)client.Client.RemoteEndPoint;
                byte[] buffer = new byte[2048];

                try
                {
                    client.NoDelay = true;
                    NetworkStream stream = client.GetStream();
                    int read = Read(stream, buffer);
                    LogPacket("tcp probe", remote, local, buffer, read);

                    if (read > 0 && LooksLikeSkypeFallback(buffer, read))
                    {
                        RunDhBootstrapSession(client, stream, remote, local, buffer, read);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        "tcp probe {0} -> {1}:{2} error: {3}",
                        remote,
                        local.Address,
                        local.Port,
                        ex.Message);
                }
            }
        }

        private void RunDhBootstrapSession(TcpClient client, NetworkStream stream, IPEndPoint remote, IPEndPoint local, byte[] buffer, int read)
        {
            while (read < SkypeDh384Session.PublicKeyBytes)
            {
                int added = stream.Read(buffer, read, SkypeDh384Session.PublicKeyBytes - read);
                if (added == 0) throw new EndOfStreamException("Incomplete bootstrap DH hello");
                read += added;
            }
            SkypeDh384Session dh = new SkypeDh384Session(buffer, read);
            stream.Write(dh.ServerHello, 0, dh.ServerHello.Length);
            byte[] hash = ReadExactBootstrap(stream, 8);
            if (!dh.VerifyClientHash(hash, hash.Length)) throw new InvalidDataException("Bootstrap DH hash mismatch");
            stream.Write(dh.ServerHash, 0, dh.ServerHash.Length);
            byte[] early = null;
            // Account RPCs use direct RC4 immediately after DH, even on a
            // bootstrap port. Node sessions instead wait for an RC4 nonce.
            if (client.Client.Poll(500000, SelectMode.SelectRead))
            {
                early = ReadExactBootstrap(stream, 5);
                if (accountServer != null && AuthProtocolServer.IsAccountRecordPrefix(dh.SharedSecret, early))
                {
                    Console.WriteLine("bootstrap {0} -> {1}: native account RPC transport", remote, local);
                    accountServer.HandleStockSkypeAuthFrames(stream, client, dh, early, true);
                    return;
                }
            }
            using (SkypeNativeRc4.Session rc4 = new SkypeNativeRc4.Session())
            {
                byte[] handshake;
                string error;
                if (!rc4.TryMakeServerHandshake(dh.SharedSecret, out handshake, out error))
                    throw new InvalidDataException("Bootstrap RC4 setup: " + error);
                stream.Write(handshake, 0, handshake.Length);
                byte[] first = new byte[16];
                int initial = early == null ? 0 : early.Length;
                if (early != null) Buffer.BlockCopy(early, 0, first, 0, initial);
                byte[] rest = ReadExactBootstrap(stream, 16 - initial);
                Buffer.BlockCopy(rest, 0, first, initial, rest.Length);
                byte[] clear;
                if (!rc4.TryDecryptClientHandshake(dh.SharedSecret, first, first.Length, out clear, out error))
                    throw new InvalidDataException("Bootstrap RC4 handshake: " + error);
                if (clear[6] != 0 || clear[7] != 0 || clear[8] != 0 || clear[9] != 1 ||
                    clear[10] != 0 || clear[11] != 0 || clear[12] != 0 || clear[15] != 3)
                    throw new InvalidDataException("Invalid bootstrap RC4 handshake signature");
                SkypeTcpFrameBuffer framing = new SkypeTcpFrameBuffer();
                bool garbagePending = true;
                bool probeReplySent = false;
                Stopwatch lifetime = Stopwatch.StartNew();
                string closeReason = "peer-eof";
                stream.ReadTimeout = 120000;
                try
                {
                    ProcessBootstrapFrames(stream, rc4, remote, local, framing.Append(clear, 14, 2),
                        ref garbagePending, ref probeReplySent);
                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (!rc4.TryDecryptFromClient(buffer, read, out clear, out error))
                            throw new InvalidDataException("Bootstrap RC4 stream: " + error);
                        ProcessBootstrapFrames(stream, rc4, remote, local, framing.Append(clear, 0, clear.Length),
                            ref garbagePending, ref probeReplySent);
                    }
                    if (framing.HasPartialFrame) closeReason = "peer-eof-mid-frame";
                }
                catch (IOException ex)
                {
                    SocketException socket = ex.InnerException as SocketException;
                    closeReason = socket == null ? "io-error" : socket.SocketErrorCode.ToString();
                    throw;
                }
                finally
                {
                    Console.WriteLine("bootstrap session {0} -> {1} closed: {2}, lifetime-ms={3}",
                        remote, local, closeReason, lifetime.ElapsedMilliseconds);
                }
            }
        }

        private static byte[] ReadExactBootstrap(NetworkStream stream, int count)
        {
            byte[] result = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(result, offset, count - offset);
                if (read == 0) throw new EndOfStreamException("Incomplete bootstrap handshake");
                offset += read;
            }
            return result;
        }

        private void ProcessBootstrapFrames(NetworkStream stream, SkypeNativeRc4.Session rc4,
            IPEndPoint remote, IPEndPoint local, List<byte[]> frames, ref bool garbagePending, ref bool probeReplySent)
        {
            foreach (byte[] frame in frames)
            {
                if (garbagePending) { garbagePending = false; continue; }
                SkypeNodeFrame parsed = SkypeNodeFrame.Decode(frame);
                if (parsed.IsAcknowledgment) continue;
                bool acknowledge = false;
                foreach (SkypeNodeCommand command in parsed.Commands)
                {
                    Console.WriteLine("bootstrap decoded {0} seq={1:X4} command=0x{2:X} flags={3} request={4} fields={5}",
                        remote, parsed.Sequence, command.Code, command.Flags,
                        command.RequestId.HasValue ? command.RequestId.Value.ToString("X4") : "none", DescribeNodeFields(command.Fields));
                    acknowledge |= command.Flags == 1;
                    SkypeNodeCommand recordReply = recordDirectory.Handle(command, DateTime.UtcNow);
                    if (recordReply != null)
                        SendEncryptedRc4Data(stream, rc4, remote, local, "directory-record-reply",
                            SkypeNodeFrame.Encode(NextServerSequence(), recordReply));
                    SkypeNodeCommand slotReply = NativeNodeDirectory.SlotReply(command,
                        advertisedAddress == null ? local : new IPEndPoint(advertisedAddress, local.Port));
                    if (slotReply != null)
                        SendEncryptedRc4Data(stream, rc4, remote, local, "slot-directory-reply",
                            SkypeNodeFrame.Encode(NextServerSequence(), slotReply));
                }
                if (acknowledge)
                    SendEncryptedRc4Data(stream, rc4, remote, local, "node-transport-ack", SkypeNodeFrame.Acknowledge(parsed.Sequence));
                Console.WriteLine("bootstrap frame {0} -> {1}, bytes={2}, data {3}",
                    remote, local, frame.Length, Hex(frame, 0, Math.Min(frame.Length, 128)));
                LogSkypeTcpFrame("bootstrap command", remote, local, frame);
                byte[] reply;
                if (!probeReplySent && TryBuildSupernodeProbeReply(frame, remote, local, out reply))
                {
                    SendEncryptedRc4Data(stream, rc4, remote, local, "bootstrap-reply", reply);
                    probeReplySent = true;
                }
            }
        }

        private static string DescribeNodeFields(List<SkypeField> fields, int depth = 0)
        {
            StringBuilder result = new StringBuilder();
            foreach (SkypeField field in fields)
            {
                if (result.Length > 2048) { result.Append(" ..."); break; }
                if (result.Length != 0) result.Append(',');
                result.Append(field.Type).Append('/').Append(field.Id.ToString("X"));
                if (field.Type == 0) result.Append('=').Append(field.Number);
                else if (field.Type == 5 && depth < 3)
                    result.Append('{').Append(DescribeNodeFields(field.Children, depth + 1)).Append('}');
                else if (field.Type == 5) result.Append('{').Append(field.Children.Count).Append('}');
                else if (field.Type == 6)
                {
                    result.Append('[');
                    for (int i = 0; i < Math.Min(field.Bytes.Length, 64); i += 4)
                    {
                        if (i != 0) result.Append(',');
                        result.Append(BitConverter.ToUInt32(field.Bytes, i));
                    }
                    if (field.Bytes.Length > 64) result.Append("...");
                    result.Append(']');
                }
                else result.Append('[').Append(field.Bytes.Length).Append(']');
            }
            return result.ToString();
        }

        // Retained only as a historical capture experiment; never used by live sessions.
        private static void RunScriptedFallbackProbe(NetworkStream stream, IPEndPoint remote, IPEndPoint local, byte[] buffer, int read)
        {
            SkypeDh384Session dh = TryCreateDhSession(buffer, read);
            SkypeNativeRc4.Session rc4 = null;
            if (dh != null)
            {
                SendScripted(stream, remote, local, "dh384-hello", dh.ServerHello);
            }
            else
            {
                SendScripted(stream, remote, local, "crypto-hello", FallbackCryptoHelloResponse);
            }

            bool ackSent = false;
            bool rc4ServerHandshakeSent = false;
            bool rc4ClientHandshakeSeen = false;
            bool supernodeProbeReplySent = false;
            bool sslHelloSent = false;
            DateTime deadline = DateTime.UtcNow.AddSeconds(18);

            try
            {
                while (DateTime.UtcNow < deadline)
                {
                    read = Read(stream, buffer);
                    if (read <= 0)
                    {
                        if (!ackSent)
                        {
                            SendScripted(stream, remote, local, "crypto-ack-timeout", dh != null ? dh.ServerHash : FallbackCryptoAckResponse);
                            ackSent = true;
                            continue;
                        }

                        break;
                    }

                    LogPacket("tcp probe next", remote, local, buffer, read);

                    if (!ackSent && read <= 16)
                    {
                        if (dh != null)
                        {
                            bool ok = dh.VerifyClientHash(buffer, read);
                            byte[] expected = dh.ExpectedClientHash;
                            Console.WriteLine(
                                "tcp probe dh384 client-hash {0} {1} -> {2}:{3}, expected {4}, got {5}",
                                ok ? "ok" : "mismatch",
                                remote,
                                local.Address,
                                local.Port,
                                Hex(expected, 0, expected.Length),
                                Hex(buffer, 0, Math.Min(read, expected.Length)));
                            SendScripted(stream, remote, local, ok ? "dh384-ack" : "dh384-ack-mismatch", dh.ServerHash);
                            if (ok)
                            {
                                rc4 = new SkypeNativeRc4.Session();
                                byte[] rc4Handshake;
                                string error;
                                if (rc4.TryMakeServerHandshake(dh.SharedSecret, out rc4Handshake, out error))
                                {
                                    SendScripted(stream, remote, local, "rc4-server-handshake", rc4Handshake);
                                    rc4ServerHandshakeSent = true;
                                }
                                else
                                {
                                    Console.WriteLine("tcp probe rc4-server-handshake skipped: {0}", error);
                                }
                            }
                        }
                        else
                        {
                            SendScripted(stream, remote, local, "crypto-ack", FallbackCryptoAckResponse);
                        }

                        ackSent = true;
                        continue;
                    }

                    if (rc4ServerHandshakeSent && !rc4ClientHandshakeSeen && read >= 16 && !LooksLikeSsl2ClientHello(buffer, read))
                    {
                        rc4ClientHandshakeSeen = true;
                        byte[] decryptedHandshake = LogDecryptedRc4Handshake(dh, rc4, remote, local, buffer, read);
                        byte[] trailingFrame;
                        if (!supernodeProbeReplySent && TryExtractTrailingFrameFromClientHandshake(decryptedHandshake, out trailingFrame))
                        {
                            Console.WriteLine(
                                "tcp probe rc4-client-handshake-trailing {0} -> {1}:{2} bytes: {3}, decrypted {4}",
                                remote,
                                local.Address,
                                local.Port,
                                trailingFrame.Length,
                                Hex(trailingFrame, 0, Math.Min(trailingFrame.Length, 128)));
                            LogSkypeTcpFrame("tcp probe rc4-client-handshake-trailing-frame", remote, local, trailingFrame);

                            byte[] clearReply;
                            if (TryBuildSupernodeProbeReply(trailingFrame, remote, local, out clearReply))
                            {
                                SendEncryptedRc4Data(stream, rc4, remote, local, "rc4-supernode-probe-reply", clearReply);
                                supernodeProbeReplySent = true;
                            }
                        }

                        continue;
                    }

                    if (rc4ServerHandshakeSent && rc4ClientHandshakeSeen)
                    {
                        byte[] decrypted = LogDecryptedRc4Data(rc4, remote, local, buffer, read);
                        if (!supernodeProbeReplySent && decrypted != null)
                        {
                            LogSkypeTcpFrame("tcp probe rc4-client-frame", remote, local, decrypted);

                            byte[] clearReply;
                            if (TryBuildSupernodeProbeReply(decrypted, remote, local, out clearReply))
                            {
                                SendEncryptedRc4Data(stream, rc4, remote, local, "rc4-supernode-probe-reply", clearReply);
                                supernodeProbeReplySent = true;
                            }
                        }

                        continue;
                    }

                    if (!sslHelloSent && (LooksLikeSsl2ClientHello(buffer, read) || (!rc4ServerHandshakeSent && ackSent && read >= 24)))
                    {
                        SendScripted(stream, remote, local, "ssl-server-hello", FallbackSslServerHelloResponse);
                        SendScripted(stream, remote, local, "crypto-connected", FallbackCryptoConnectedResponse);
                        sslHelloSent = true;
                        continue;
                    }
                }
            }
            finally
            {
                if (rc4 != null)
                {
                    rc4.Dispose();
                }
            }
        }

        private static byte[] LogDecryptedRc4Handshake(SkypeDh384Session dh, SkypeNativeRc4.Session rc4, IPEndPoint remote, IPEndPoint local, byte[] buffer, int read)
        {
            byte[] decrypted;
            string error = "missing dh session";
            if (dh != null && rc4 != null && rc4.TryDecryptClientHandshake(dh.SharedSecret, buffer, read, out decrypted, out error))
            {
                Console.WriteLine(
                    "tcp probe rc4-client-handshake {0} -> {1}:{2} bytes: {3}, decrypted {4}",
                    remote,
                    local.Address,
                    local.Port,
                    read,
                    Hex(decrypted, 0, Math.Min(decrypted.Length, 128)));
                return decrypted;
            }
            else
            {
                Console.WriteLine(
                    "tcp probe rc4-client-handshake {0} -> {1}:{2} bytes: {3}, decrypt failed: {4}",
                    remote,
                    local.Address,
                    local.Port,
                    read,
                    error);
                return null;
            }
        }

        private static byte[] LogDecryptedRc4Data(SkypeNativeRc4.Session rc4, IPEndPoint remote, IPEndPoint local, byte[] buffer, int read)
        {
            byte[] decrypted;
            string error = "missing rc4 session";
            if (rc4 != null && rc4.TryDecryptFromClient(buffer, read, out decrypted, out error))
            {
                Console.WriteLine(
                    "tcp probe rc4-client-data {0} -> {1}:{2} bytes: {3}, decrypted {4}",
                    remote,
                    local.Address,
                    local.Port,
                    read,
                    Hex(decrypted, 0, Math.Min(decrypted.Length, 128)));
                return decrypted;
            }
            else
            {
                Console.WriteLine(
                    "tcp probe rc4-client-data {0} -> {1}:{2} bytes: {3}, decrypt failed: {4}",
                    remote,
                    local.Address,
                    local.Port,
                    read,
                    error);
                return null;
            }
        }

        private static bool TryBuildSupernodeProbeReply(byte[] request, IPEndPoint remote, IPEndPoint local, out byte[] reply)
        {
            reply = null;
            if (!LooksLikeSkypeTcpFrame(request))
            {
                return false;
            }

            byte commandHi = request[4];
            byte commandLo = request[5];
            if (commandHi == 0xF2 && commandLo == 0x01)
            {
                return TryBuildCommand30Reply(request, remote, local, out reply);
            }

            if (commandHi != 0xCA || commandLo != 0x04)
            {
                return false;
            }

            ushort clientPreviousSequence = ReadUInt16BigEndian(request, 6);
            byte[] payload = SupernodeProbePayload;

            reply = new byte[8 + payload.Length];
            reply[0] = (byte)((reply.Length - 1) << 1);
            WriteUInt16BigEndian(reply, 1, NextServerSequence());
            reply[3] = (byte)(payload.Length + 2);
            reply[4] = 0xDB;
            reply[5] = 0x04;
            WriteUInt16BigEndian(reply, 6, clientPreviousSequence);
            Buffer.BlockCopy(payload, 0, reply, 8, payload.Length);
            return true;
        }

        internal static bool TryBuildCommand30Reply(byte[] request, IPEndPoint remote, IPEndPoint local, out byte[] reply)
        {
            reply = null;
            if (!LooksLikeSkypeTcpFrame(request) || request[4] != 0xf2 || request[5] != 1)
            {
                return false;
            }

            ushort requestSequence = ReadUInt16BigEndian(request, 6);

            byte[] publicIpReply = FromHex(
                "D1 21 FB 01 00 00 41 06 00 0B 34 00 0C EC D1 93 " +
                "D0 05 02 11 75 03 25 C7 06 94 00 10 D5 B8 02 00 " +
                "2C 01 06 21 00");

            // skysearch4_dll/tcp_setup.c reads 2/11 as MY_ADDR. A historical
            // endpoint here causes every client to learn an unrelated public IP.
            if (remote == null || remote.Address.AddressFamily != AddressFamily.InterNetwork)
                throw new InvalidDataException("Expected an observed IPv4 bootstrap endpoint");
            if (local == null || local.Address.AddressFamily != AddressFamily.InterNetwork || local.Port == 0)
                throw new InvalidDataException("Expected a listening IPv4 bootstrap endpoint");
            byte[] encoded = new byte[publicIpReply.Length - 6];
            Buffer.BlockCopy(publicIpReply, 6, encoded, 0, encoded.Length);
            int consumed;
            List<SkypeField> fields = SkypeBlobCodec.Decode(encoded, out consumed);
            if (consumed != encoded.Length) throw new InvalidDataException("Trailing bootstrap address fields");
            SkypeField endpoint = SkypeBlobCodec.Required(fields, 2, 0x11);
            Buffer.BlockCopy(remote.Address.GetAddressBytes(), 0, endpoint.Bytes, 0, 4);
            WriteUInt16BigEndian(endpoint.Bytes, 4, (ushort)remote.Port);
            // Skype 4.2 HostScanner::reply (00780AC0) consumes 0/10 as
            // the parent port. Never advertise a port from an old capture.
            SkypeBlobCodec.Required(fields, 0, 0x10).Number = (uint)local.Port;
            byte[] updated = SkypeBlobCodec.Encode(fields);
            publicIpReply = new byte[8 + updated.Length];
            publicIpReply[0] = checked((byte)((publicIpReply.Length - 1) << 1));
            WriteUInt16BigEndian(publicIpReply, 1, NextServerSequence());
            publicIpReply[3] = checked((byte)(updated.Length + 2));
            publicIpReply[4] = 0xfb;
            publicIpReply[5] = 1;
            WriteUInt16BigEndian(publicIpReply, 6, requestSequence);
            Buffer.BlockCopy(updated, 0, publicIpReply, 8, updated.Length);
            // Do not replay the captured 0x2F BCM inventory or user count.
            // Native 006BCF60 requests its advertised revisions with 0x30;
            // 006BCAE0 expects signed content in 4/3, not a keepalive echo.
            // This node has no BCM documents to advertise or serve yet.
            reply = publicIpReply;
            return true;
        }

        private static bool LooksLikeSkypeTcpFrame(byte[] packet)
        {
            if (packet == null || packet.Length < 9)
            {
                return false;
            }

            int declaredLength = (packet[0] >> 1) + 1;
            return declaredLength == packet.Length &&
                   packet[3] == packet.Length - 6 &&
                   packet[8] == 0x42;
        }

        private static void LogSkypeTcpFrame(string prefix, IPEndPoint remote, IPEndPoint local, byte[] packet)
        {
            if (!LooksLikeSkypeTcpFrame(packet))
            {
                return;
            }

            int declaredLength = (packet[0] >> 1) + 1;
            ushort crcOrSeq = ReadUInt16BigEndian(packet, 1);
            int bodyLength = packet[3];
            ushort command = ReadUInt16BigEndian(packet, 4);
            ushort previousSequence = ReadUInt16BigEndian(packet, 6);
            int payloadLength = packet.Length - 8;

            Console.WriteLine(
                "{0} {1} -> {2}:{3} len={4} declared={5} crc/seq={6:X4} body={7} cmd={8:X4} prev={9:X4} tag={10:X2} payload={11}",
                prefix,
                remote,
                local.Address,
                local.Port,
                packet.Length,
                declaredLength,
                crcOrSeq,
                bodyLength,
                command,
                previousSequence,
                packet[8],
                Hex(packet, 8, Math.Min(payloadLength, 32)));
        }

        private static bool TryExtractTrailingFrameFromClientHandshake(byte[] packet, out byte[] trailingFrame)
        {
            trailingFrame = null;
            if (packet == null || packet.Length < 17 || packet[15] != 0x03)
            {
                return false;
            }

            int garbageLengthCode = packet[14];
            if ((garbageLengthCode & 1) == 0 || garbageLengthCode < 3)
            {
                return false;
            }

            int garbageLength = (garbageLengthCode - 3) / 2;
            int consumed = 16 + garbageLength;
            if (consumed >= packet.Length)
            {
                return false;
            }

            int trailingLength = packet.Length - consumed;
            trailingFrame = new byte[trailingLength];
            Buffer.BlockCopy(packet, consumed, trailingFrame, 0, trailingLength);
            return LooksLikeSkypeTcpFrame(trailingFrame);
        }

        private static void SendEncryptedRc4Data(NetworkStream stream, SkypeNativeRc4.Session rc4, IPEndPoint remote, IPEndPoint local, string name, byte[] clear)
        {
            byte[] encrypted;
            string error = "missing rc4 session";
            if (rc4 != null && rc4.TryEncryptToClient(clear, clear.Length, out encrypted, out error))
            {
                Console.WriteLine(
                    "tcp probe clear {0}:{1} -> {2} {3} bytes: {4}, data {5}",
                    local.Address,
                    local.Port,
                    remote,
                    name,
                    clear.Length,
                    Hex(clear, 0, Math.Min(clear.Length, 64)));
                SendScripted(stream, remote, local, name, encrypted);
            }
            else
            {
                Console.WriteLine(
                    "tcp probe {0}:{1} -> {2} {3} encrypt failed: {4}",
                    local.Address,
                    local.Port,
                    remote,
                    name,
                    error);
            }
        }

        private static ushort NextServerSequence()
        {
            return (ushort)(Interlocked.Increment(ref nextServerSequence) & 0xFFFF);
        }

        private static ushort ReadUInt16BigEndian(byte[] data, int offset)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        private static void WriteUInt16BigEndian(byte[] data, int offset, ushort value)
        {
            data[offset] = (byte)(value >> 8);
            data[offset + 1] = (byte)value;
        }

        private static SkypeDh384Session TryCreateDhSession(byte[] buffer, int read)
        {
            if (read < SkypeDh384Session.PublicKeyBytes)
            {
                return null;
            }

            try
            {
                return new SkypeDh384Session(buffer, read);
            }
            catch (Exception ex)
            {
                Console.WriteLine("tcp probe dh384 setup failed: {0}", ex.Message);
                return null;
            }
        }

        private static int Read(NetworkStream stream, byte[] buffer)
        {
            try
            {
                return stream.Read(buffer, 0, buffer.Length);
            }
            catch (SocketException)
            {
                return 0;
            }
            catch (System.IO.IOException)
            {
                return 0;
            }
        }

        private static void SendScripted(NetworkStream stream, IPEndPoint remote, IPEndPoint local, string name, byte[] data)
        {
            try
            {
                stream.Write(data, 0, data.Length);
                Console.WriteLine(
                    "tcp probe scripted {0}:{1} -> {2} {3} bytes: {4}, data {5}",
                    local.Address,
                    local.Port,
                    remote,
                    name,
                    data.Length,
                    Hex(data, 0, Math.Min(data.Length, 64)));
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    "tcp probe scripted {0}:{1} -> {2} {3} failed: {4}",
                    local.Address,
                    local.Port,
                    remote,
                    name,
                    ex.Message);
            }
        }

        private static void LogPacket(string prefix, IPEndPoint remote, IPEndPoint local, byte[] buffer, int read)
        {
            string details = read > 0
                ? String.Format(", data {0}, ascii {1}", Hex(buffer, 0, Math.Min(read, 64)), AsciiPreview(buffer, 0, Math.Min(read, 64)))
                : "";
            Console.WriteLine("{0} {1} -> {2}:{3} bytes: {4}{5}", prefix, remote, local.Address, local.Port, read, details);
        }

        private static bool LooksLikeSkypeFallback(byte[] buffer, int read)
        {
            if (read < 8)
            {
                return false;
            }

            if (StartsWithAscii(buffer, read, "GET ") ||
                StartsWithAscii(buffer, read, "POST ") ||
                StartsWithAscii(buffer, read, "HEAD ") ||
                StartsWithAscii(buffer, read, "CONNECT ") ||
                StartsWithAscii(buffer, read, "OPTIONS "))
            {
                return false;
            }

            if (read >= 3 && buffer[0] == 0x16 && buffer[1] == 0x03)
            {
                return false;
            }

            return true;
        }

        private static bool LooksLikeSsl2ClientHello(byte[] buffer, int read)
        {
            return read >= 8 && buffer[0] == 0x80 && buffer[2] == 0x01 && buffer[3] == 0x03;
        }

        private static bool StartsWithAscii(byte[] buffer, int read, string value)
        {
            if (read < value.Length)
            {
                return false;
            }

            for (int i = 0; i < value.Length; i++)
            {
                if (buffer[i] != (byte)value[i])
                {
                    return false;
                }
            }

            return true;
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

        private static byte[] FromHex(string hex)
        {
            List<byte> bytes = new List<byte>();
            string[] parts = hex.Split(new char[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++)
            {
                bytes.Add(Convert.ToByte(parts[i], 16));
            }

            return bytes.ToArray();
        }
    }
}
