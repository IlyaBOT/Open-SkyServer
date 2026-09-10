using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SkyServer;

internal static class NativeLoginTests
{
    internal static void Run(string root, SkyDatabase database)
    {
        string directory = Path.Combine(root, "native-test-authority");
        Directory.CreateDirectory(directory);
        DirectorySecurity acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.SetAccessControl(directory, acl);
        try
        {
            Generate(directory, "login", 1536);
            Generate(directory, "credentials", 2048);
            CommunityKeys keys = CommunityKeys.Load(directory);
            RSAParameters authority;
            using (RSACryptoServiceProvider pub = new RSACryptoServiceProvider())
            {
                pub.PersistKeyInCsp = false;
                pub.FromXmlString(File.ReadAllText(Path.Combine(directory, "credentials.public.xml")));
                authority = pub.ExportParameters(false);
            }
            NativeCredentialsTests.Run(keys, authority);
            database.AddAccount("native.test", "Native Test", "native-password");
            byte[] digest = SkyDatabase.NativePasswordDigest("native.test", "native-password");
            Check(database.ValidateNativePasswordHash("native.test", digest), "native DB verifier");
            Check(!database.ValidateNativePasswordHash("native.test", new byte[16]), "wrong native digest");
            Check(!database.ValidateNativePasswordHash("unknown", digest), "unknown native account");
            Check(!database.ValidateNativePasswordHash("native.test", new byte[15]), "short native digest");
            string stored = Query(database, "SELECT verifier FROM native_password_verifiers WHERE login='native.test';");
            Check(stored.Trim() != Convert.ToBase64String(digest), "raw password MD5 is not stored");
            Execute(database, "DELETE FROM native_password_verifiers WHERE login='native.test';");
            Check(!database.ValidateNativePasswordHash("native.test", digest), "unprovisioned legacy account fails closed");
            Check(!database.ValidatePassword("native.test", "wrong"), "wrong plaintext password");
            Check(!database.ValidateNativePasswordHash("native.test", digest), "wrong plaintext cannot provision native verifier");
            Check(database.ValidatePassword("native.test", "native-password"), "verified plaintext migration");
            Check(database.ValidateNativePasswordHash("native.test", digest), "legacy account provisioned after valid plaintext login");
            database.AddContact("native.test", "transport.test");
            database.AddAccount("native.test", "Native Test", "new-password");
            Check(!database.ValidateNativePasswordHash("native.test", digest), "rotation invalidates old native verifier");
            Check(database.ValidateNativePasswordHash("native.test", SkyDatabase.NativePasswordDigest("native.test", "new-password")), "rotated native verifier");
            Check(database.GetContacts("native.test").Count == 1, "rotation preserves contacts");
            database.AddAccount("native.test", "Native Test", "native-password");

            byte[] material = new byte[192];
            for (int i = 0; i < material.Length; i++) material[i] = (byte)(i % 24);
            material[0] = 1;
            byte[] cipher;
            using (RSACryptoServiceProvider pub = new RSACryptoServiceProvider())
            {
                pub.PersistKeyInCsp = false;
                pub.FromXmlString(File.ReadAllText(Path.Combine(directory, "login.public.xml")));
                cipher = CommunityKeys.PublicOperation(material, pub.ExportParameters(false));
            }
            byte[] compressed = Join(Hex("42CDEFE740D72F1DC0C68880DFB77537186962B4EE3E"), cipher,
                Hex("7D8AF308D936AF94F5A22BE0E9063FE40572BB30E1"));
            int consumed;
            List<SkypeField> exchange = SkypeBlobCodec.Decode(compressed, out consumed);
            Check(consumed == compressed.Length, "42 key-exchange consumption");
            Check(Equal(SkypeBlobCodec.Required(exchange, 4, 8).Bytes, cipher), "42 RSA field matches source layout");
            byte[] clientKey = new byte[128];
            clientKey[0] = 0x91; clientKey[127] = 3;
            byte[] clear = LoginPayload(digest, clientKey, 0x13a3, false);
            byte[] record1 = Record(0x16, compressed);
            byte[] record2 = Protect(clear, material);
            using (NativeLoginRequest request = NativeLoginRequest.Parse(record1, record2, keys))
            {
                Check(request.Username == "native.test", "native username");
                Check(Equal(request.PasswordDigest, digest), "native password digest");
                Check(Equal(request.ClientPublicKey, clientKey), "native client public key");
                Check(database.ValidateNativePasswordHash(request.Username, request.PasswordDigest), "decoded native request validates against DB");
            }
            NativeLoginRequest disposed = NativeLoginRequest.Parse(record1, record2, keys);
            disposed.Dispose();
            Check(Equal(disposed.PasswordDigest, new byte[16]) && Equal(disposed.AesKey, new byte[32]), "request disposal clears secrets");
            byte[] legacyLogin = Protect(LoginPayload(digest, clientKey, 0x1399, false), material);
            using (NativeLoginRequest legacy = NativeLoginRequest.Parse(record1, legacyLogin, keys))
            {
                Check(legacy.Username == "native.test" && Equal(legacy.ClientPublicKey, clientKey), "4.2 login operation");
                Check(database.ValidateNativePasswordHash(legacy.Username, legacy.PasswordDigest), "4.2 operation uses DB verification");
            }
            string shape = NativeLoginRequest.DescribeFields(new List<SkypeField> {
                new SkypeField { Type = 3, Id = 4, Bytes = Encoding.UTF8.GetBytes("do-not-log-me") },
                new SkypeField { Type = 4, Id = 5, Bytes = digest },
                new SkypeField { Type = 0, Id = 2, Number = 0xdeadbeef }
            });
            Check(shape == "3:4[13],4:5[16],0:2", "auth diagnostic contains structure only");
            byte[] corrupt = (byte[])record2.Clone(); corrupt[corrupt.Length - 1] ^= 1;
            ProtocolTests.RunCommunityTransport("native community RSA/AES returns a verifiable signed credential", keys, record1, record2, null, 292,
                delegate(byte[] response) {
                    NativeCredentialsTests.CheckResponse(response, CommunityKeys.DeriveLoginAesKey(material),
                        authority, "native.test", clientKey, DateTime.UtcNow);
                });
            ProtocolTests.RunCommunityTransport("native community transport rejects corrupted CRC", keys, record1, corrupt, typeof(InvalidDataException));
            ProtocolTests.RunCommunityTransport("4.2 native login returns a signed credential", keys, record1, legacyLogin, null, 292,
                delegate(byte[] response) {
                    NativeCredentialsTests.CheckResponse(response, CommunityKeys.DeriveLoginAesKey(material),
                        authority, "native.test", clientKey, DateTime.UtcNow);
                });
            ProtocolTests.RunCommunityTransport("native community transport rejects wrong password digest", keys, record1,
                Protect(LoginPayload(new byte[16], clientKey, 0x13a3, false), material), null);
            Check(database.GetAccountEmail("native.test") == "", "unset email is empty DB state");
            database.SetAccountEmail("native.test", "profile@example.test");
            Check(database.GetAccountEmail("native.test") == "profile@example.test", "email is separate from username");
            byte[] emailRequest = Protect(LoginPayload(digest, null, 0x139c, false, 2), material);
            using (NativeLoginRequest email = NativeLoginRequest.Parse(record1, emailRequest, keys))
                Check(email.Operation == 0x139c && email.RequestId == 2 && email.ClientPublicKey == null, "email query has no credential modulus");
            ProtocolTests.RunCommunityTransport("4.2 email query returns verified DB profile data", keys, record1, emailRequest, null,
                NativeCredentials.EmailPayload("profile@example.test", 2).Length + 7, delegate(byte[] response) {
                    byte[] cipherText = new byte[response.Length - 7];
                    Buffer.BlockCopy(response, 5, cipherText, 0, cipherText.Length);
                    byte[] result = CommunityKeys.LoginAesCtr(CommunityKeys.DeriveLoginAesKey(material), cipherText, 1);
                    Check(Equal(result, NativeCredentials.EmailPayload("profile@example.test", 2)), "email response contents and request identifier");
                });
            using (NativeLoginRequest largeId = NativeLoginRequest.Parse(record1,
                Protect(LoginPayload(digest, clientKey, 0x1399, false, UInt32.MaxValue), material), keys))
                Check(largeId.RequestId == UInt32.MaxValue, "full-width request identifier");
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(LoginPayload(digest, clientKey, 0x1399, false, 0), material), keys); },
                "zero request identifier");
            ProtocolTests.RunCommunityTransport("4.2 email query rejects wrong password", keys, record1,
                Protect(LoginPayload(new byte[16], null, 0x139c, false), material), null);
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(LoginPayload(digest, null, 0x1399, false), material), keys); },
                "login still requires a client modulus");
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(LoginPayload(digest, null, 0x139c, true), material), keys); },
                "email query rejects duplicate username");
            Reject(delegate { NativeLoginRequest.Parse(record1, corrupt, keys); }, "ciphertext CRC");
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(LoginPayload(digest, clientKey, 1, false), material), keys); }, "unsupported operation");
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(LoginPayload(digest, clientKey, 0x13a3, true), material), keys); }, "duplicate username");
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(LoginPayload(digest, clientKey, 0x1399, true), material), keys); }, "duplicate 4.2 username");
            clientKey[127] = 2;
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(LoginPayload(digest, clientKey, 0x13a3, false), material), keys); }, "even client modulus");
            byte[] wrongMaterial = (byte[])material.Clone(); wrongMaterial[5] ^= 1;
            Reject(delegate { NativeLoginRequest.Parse(record1, Protect(clear, wrongMaterial), keys); }, "wrong AES session key");
            Reject(delegate { int used; SkypeBlobCodec.Decode(new byte[] { 0x41, 1, 4, 8, 0xff, 0xff, 0xff, 0xff, 0x10 }, out used); }, "overflow blob length");
            Reject(delegate { int used; SkypeBlobCodec.Decode(new byte[] { 0x41, 1, 3, 4, 65 }, out used); }, "unterminated string");
            Reject(delegate { int used; SkypeBlobCodec.Decode(new byte[] { 0x42 }, out used); }, "truncated compressed blob");
            for (int count = 2; count <= 16; count++)
            {
                byte[] shortPacket = new byte[count];
                Buffer.BlockCopy(compressed, 0, shortPacket, 0, count);
                Reject(delegate { int used; SkypeBlobCodec.Decode(shortPacket, out used); }, "truncated 42 exchange " + count);
            }
            Execute(database, "UPDATE accounts SET is_active=0 WHERE login='native.test';");
            Check(!database.ValidateNativePasswordHash("native.test", digest), "inactive native account");
            database.RemoveAccount("native.test");
            Check(Query(database, "SELECT COUNT(*) FROM native_password_verifiers WHERE login='native.test';").Trim() == "0", "native verifier cascades on removal");
            Check(Query(database, "SELECT COUNT(*) FROM account_profiles WHERE login='native.test';").Trim() == "0", "email cascades on removal");
            Console.WriteLine("PASS native login tests: original 42 layout, RSA/AES/CRC parsing, salted DB verifiers, migration, signed response and rejection paths. No real-client login is claimed.");
        }
        finally
        {
            foreach (string name in new[] { "login.private.xml", "login.public.xml", "credentials.private.xml", "credentials.public.xml" })
                File.Delete(Path.Combine(directory, name));
            Directory.Delete(directory, false);
        }
    }

    private static byte[] LoginPayload(byte[] digest, byte[] clientKey, uint operation, bool duplicateUser, uint requestId = 1)
    {
        using (MemoryStream output = new MemoryStream())
        {
            output.WriteByte(0x41); output.WriteByte((byte)(duplicateUser ? 5 : 4));
            output.WriteByte(0); output.WriteByte(0); Varint(output, operation);
            output.WriteByte(0); output.WriteByte(2); Varint(output, requestId);
            output.WriteByte(3); output.WriteByte(4); Write(output, Encoding.UTF8.GetBytes("native.test\0"));
            if (duplicateUser) { output.WriteByte(3); output.WriteByte(4); Write(output, Encoding.UTF8.GetBytes("duplicate\0")); }
            output.WriteByte(4); output.WriteByte(5); Varint(output, (uint)digest.Length); Write(output, digest);
            output.WriteByte(0x41); output.WriteByte((byte)(clientKey == null ? 0 : 1));
            if (clientKey != null)
            {
                output.WriteByte(4); output.WriteByte(0x21); Varint(output, (uint)clientKey.Length); Write(output, clientKey);
            }
            return output.ToArray();
        }
    }

    private static byte[] Protect(byte[] clear, byte[] material)
    {
        byte[] cipher = CommunityKeys.LoginAesCtr(CommunityKeys.DeriveLoginAesKey(material), clear, 0);
        uint crc = NativeLoginRequest.Crc(cipher, cipher.Length);
        return Record(0x17, Join(cipher, new[] { (byte)crc, (byte)(crc >> 8) }));
    }

    private static byte[] Record(byte type, byte[] payload)
    {
        return Join(new[] { type, (byte)3, (byte)1, (byte)(payload.Length >> 8), (byte)payload.Length }, payload);
    }
    private static void Varint(Stream stream, uint value)
    {
        while (value >= 128) { stream.WriteByte((byte)(value | 128)); value >>= 7; }
        stream.WriteByte((byte)value);
    }
    private static byte[] Join(params byte[][] arrays)
    {
        using (MemoryStream result = new MemoryStream()) { foreach (byte[] data in arrays) Write(result, data); return result.ToArray(); }
    }
    private static void Write(Stream stream, byte[] bytes) { stream.Write(bytes, 0, bytes.Length); }
    private static byte[] Hex(string value)
    {
        byte[] data = new byte[value.Length / 2];
        for (int i = 0; i < data.Length; i++) data[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
        return data;
    }
    private static bool Equal(byte[] a, byte[] b) { return Convert.ToBase64String(a) == Convert.ToBase64String(b); }
    private static void Check(bool value, string label) { if (!value) throw new Exception("Failed: " + label); }
    private static void Reject(Action action, string label)
    {
        try { action(); }
        catch (InvalidDataException) { return; }
        catch (CryptographicException) { return; }
        catch (DecoderFallbackException) { return; }
        throw new Exception("Expected rejection: " + label);
    }
    private static void Generate(string directory, string name, int bits)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(bits))
        {
            rsa.PersistKeyInCsp = false;
            File.WriteAllText(Path.Combine(directory, name + ".private.xml"), rsa.ToXmlString(true));
            File.WriteAllText(Path.Combine(directory, name + ".public.xml"), rsa.ToXmlString(false));
        }
    }
    private static void Execute(SkyDatabase database, string sql)
    {
        typeof(SkyDatabase).GetMethod("Execute", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(database, new object[] { sql });
    }
    private static string Query(SkyDatabase database, string sql)
    {
        return (string)typeof(SkyDatabase).GetMethod("QuerySingle", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(database, new object[] { sql });
    }
}
