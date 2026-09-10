using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using SkyServer;

internal static class ProtocolTests
{
    private static SkyDatabase database;
    private static string databasePath;
    private static string sqlite;
    private static int passed;
    private static readonly BigInteger Modulus = FromBigEndian(Hex(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B13B202FFFFFFFFFFFFFFFF"));

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length != 2) throw new ArgumentException("Usage: ProtocolTests.exe sqlite3.exe output-directory");
            sqlite = args[0];
            Directory.CreateDirectory(args[1]);
            CommunityKeysTests.Run(args[1]);
            UdpDestinationTests.Run();
            databasePath = Path.Combine(Path.GetFullPath(args[1]), "protocol-tests.db");
            if (File.Exists(databasePath)) throw new IOException("Test database already exists; use a new output directory");
            database = new SkyDatabase(databasePath, sqlite);
            database.EnsureSchema();
            database.AddAccount("transport.test", "Transport Test", "test-password");
            NativeLoginTests.Run(args[1], database);

            Run("reconstructed valid DB password", false, false, "test-password", 0, false, false, 292, 1, null);
            Run("reconstructed wrong DB password", false, false, "wrong-password", 0, false, false, 21, 0, null);
            Run("probe accepts fragmented reconstructed header", true, false, "test-password", 1, false, false, 292, 1, null);
            Run("missing local credentials cannot authenticate", true, false, null, 0, false, false, 0, 0, typeof(EndOfStreamException));
            Run("malformed login header cannot authenticate", false, false, "test-password", 0, true, false, 0, 0, typeof(InvalidDataException));
            Run("synthetic stock transport closes unauthenticated", true, true, null, 0, false, false, 0, 0, null);
            Run("synthetic stock fragmented records close unauthenticated", true, true, null, 7, false, false, 0, 0, null);
            Run("stock rejects unexpected first record type", true, true, null, 0, true, false, 0, 0, typeof(InvalidDataException));
            Run("incorrect DH hash cannot authenticate", true, true, null, 0, false, true, 0, 0, null);
            Console.WriteLine("PASS {0} protocol tests. Native tests use synthetic envelopes, not a real Skype login.", passed);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL: {0}", ex);
            return 1;
        }
    }

    internal static void RunCommunityTransport(string name, CommunityKeys keys, byte[] record1, byte[] record2, Type expectedError,
        int expectedBytes = 0, Action<byte[]> verifyResponse = null)
    {
        Run(name, true, true, null, 7, false, false, expectedBytes, 0, expectedError, keys, new[] { record1, record2 }, verifyResponse);
    }

    private static void Run(string name, bool probe, bool stock, string password,
        int fragmentation, bool badHeader, bool badHash, int expectedBytes, int expectedSessions, Type expectedError,
        CommunityKeys keys = null, byte[][] nativeRecords = null, Action<byte[]> verifyResponse = null)
    {
        int before = CountSessions();
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Exception serverError = null;
        Thread serverThread = new Thread(delegate()
        {
            try
            {
                using (TcpClient accepted = listener.AcceptTcpClient())
                {
                    AuthProtocolServer server = new AuthProtocolServer(database, IPAddress.Loopback, 0, true, probe, keys);
                    typeof(AuthProtocolServer).GetMethod("HandleClient", BindingFlags.Instance | BindingFlags.NonPublic)
                        .Invoke(server, new object[] { accepted });
                }
            }
            catch (TargetInvocationException ex) { serverError = ex.InnerException; }
            catch (Exception ex) { serverError = ex; }
        });
        serverThread.IsBackground = true;
        serverThread.Start();
        try
        {
            using (TcpClient client = new TcpClient())
            {
                client.NoDelay = true;
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;
                client.Connect((IPEndPoint)listener.LocalEndpoint);
                NetworkStream stream = client.GetStream();
                BigInteger exponent = new BigInteger(123456789);
                byte[] hello = ToBigEndian(BigInteger.ModPow(new BigInteger(2), exponent, Modulus), 48);
                stream.Write(hello, 0, hello.Length);
                byte[] serverHello = ReadExact(stream, 51);
                byte[] publicKey = new byte[48];
                Buffer.BlockCopy(serverHello, 0, publicKey, 0, 48);
                byte[] shared = ToBigEndian(BigInteger.ModPow(FromBigEndian(publicKey), exponent, Modulus), 48);
                byte[] hash = DhHash((byte)'O', shared);
                if (badHash) hash[0] ^= 1;
                stream.Write(hash, 0, hash.Length);
                if (!badHash)
                {
                    if (stock)
                    {
                        byte[] ack = ReadExact(stream, 8);
                        if (BitConverter.ToString(ack) != BitConverter.ToString(DhHash((byte)'I', shared)))
                            throw new Exception("Wrong stock DH acknowledgement");
                    }
                    byte[] first = Frame(badHeader ? (byte)0x18 : (byte)0x16, new byte[230]);
                    if (badHeader && !stock) first[1] = 0;
                    List<byte> records = new List<byte>(first);
                    records.AddRange(Frame(0x17, new byte[246]));
                    if (nativeRecords != null)
                    {
                        records.Clear();
                        foreach (byte[] record in nativeRecords) records.AddRange(record);
                    }
                    if (password != null)
                    {
                        string auth = "SKYSERVER-AUTH/1\nuser_hex=" + TextHex("transport.test") +
                            "\npass_hex=" + TextHex(password) + "\n";
                        records.AddRange(Frame(0x18, Encoding.ASCII.GetBytes(auth)));
                    }
                    byte[] encrypted = records.ToArray();
                    Crypt(shared, encrypted);
                    if (fragmentation == 1)
                    {
                        stream.Write(encrypted, 0, 1);
                        Thread.Sleep(75);
                        stream.Write(encrypted, 1, encrypted.Length - 1);
                    }
                    else if (fragmentation > 1)
                    {
                        for (int offset = 0; offset < encrypted.Length; offset += fragmentation)
                            stream.Write(encrypted, offset, Math.Min(fragmentation, encrypted.Length - offset));
                    }
                    else stream.Write(encrypted, 0, encrypted.Length);
                    client.Client.Shutdown(SocketShutdown.Send);
                }
                List<byte> received = new List<byte>();
                byte[] buffer = new byte[1024];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    for (int i = 0; i < read; i++) received.Add(buffer[i]);
                if (received.Count != expectedBytes)
                    throw new Exception(name + ": unexpected response size " + received.Count);
                if (expectedBytes > 0)
                {
                    byte[] response = received.ToArray();
                    shared[0]++;
                    Crypt(shared, response);
                    if (response[0] != 0x17 || response[1] != 3 || response[2] != 1 ||
                        ((response[3] << 8) | response[4]) != response.Length - 5)
                        throw new Exception(name + ": invalid reconstructed response header");
                    if (verifyResponse != null) verifyResponse(response);
                }
            }
        }
        finally
        {
            listener.Stop();
            if (!serverThread.Join(12000)) throw new Exception(name + ": server did not terminate");
        }
        if (expectedError == null ? serverError != null : serverError == null || serverError.GetType() != expectedError)
            throw new Exception(name + ": unexpected server exception", serverError);
        if (CountSessions() - before != expectedSessions)
            throw new Exception(name + ": wrong number of DB sessions created");
        passed++;
        Console.WriteLine("PASS: {0}", name);
    }

    private static int CountSessions()
    {
        ProcessStartInfo info = new ProcessStartInfo(sqlite, "-readonly \"" + databasePath + "\" \"SELECT COUNT(*) FROM sessions;\"");
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        using (Process process = Process.Start(info))
        {
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0) throw new Exception("SQLite test query failed: " + error);
            return Int32.Parse(output.Trim());
        }
    }

    private static byte[] Frame(byte type, byte[] payload)
    {
        byte[] result = new byte[payload.Length + 5];
        result[0] = type; result[1] = 3; result[2] = 1;
        result[3] = (byte)(payload.Length >> 8); result[4] = (byte)payload.Length;
        Buffer.BlockCopy(payload, 0, result, 5, payload.Length);
        return result;
    }

    private static byte[] ReadExact(Stream stream, int length)
    {
        byte[] result = new byte[length];
        int offset = 0;
        while (offset < length)
        {
            int read = stream.Read(result, offset, length - offset);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        return result;
    }

    private static byte[] DhHash(byte prefix, byte[] shared)
    {
        byte[] input = new byte[shared.Length + 1];
        input[0] = prefix;
        Buffer.BlockCopy(shared, 0, input, 1, shared.Length);
        byte[] digest;
        using (MD5 md5 = MD5.Create()) digest = md5.ComputeHash(input);
        byte[] result = new byte[8];
        Buffer.BlockCopy(digest, 0, result, 0, 8);
        return result;
    }

    private static void Crypt(byte[] key, byte[] data)
    {
        int[] state = new int[256];
        for (int a = 0; a < 256; a++) state[a] = a;
        int j = 0;
        for (int a = 0; a < 256; a++)
        {
            j = (j + state[a] + key[a % key.Length]) & 255;
            int swap = state[a]; state[a] = state[j]; state[j] = swap;
        }
        int i = 0; j = 0;
        for (int n = 0; n < data.Length; n++)
        {
            i = (i + 1) & 255; j = (j + state[i]) & 255;
            int swap = state[i]; state[i] = state[j]; state[j] = swap;
            data[n] ^= (byte)state[(state[i] + state[j]) & 255];
        }
    }

    private static BigInteger FromBigEndian(byte[] data)
    {
        byte[] little = new byte[data.Length + 1];
        for (int i = 0; i < data.Length; i++) little[i] = data[data.Length - i - 1];
        return new BigInteger(little);
    }

    private static byte[] ToBigEndian(BigInteger value, int length)
    {
        byte[] little = value.ToByteArray();
        byte[] result = new byte[length];
        for (int i = 0; i < Math.Min(length, little.Length); i++) result[length - i - 1] = little[i];
        return result;
    }

    private static byte[] Hex(string value)
    {
        byte[] result = new byte[value.Length / 2];
        for (int i = 0; i < result.Length; i++) result[i] = Convert.ToByte(value.Substring(2 * i, 2), 16);
        return result;
    }

    private static string TextHex(string value)
    {
        return BitConverter.ToString(Encoding.UTF8.GetBytes(value)).Replace("-", "");
    }
}
