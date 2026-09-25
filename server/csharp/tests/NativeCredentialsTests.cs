using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using SkyServer;

internal static class NativeCredentialsTests
{
    // Public authority modulus and a public login response only. No password,
    // session key or client private prime is copied from the historical log.
    private const string HistoricalAuthority =
        "B8506AEED8ED30FE1C0E6774874B59206A77329042A49BE2403DA47D50052441067F87BCD57E6579B83DF0BADE2BEFF5B5CD8D87E8B3EDAC5F57FABCCD49695974E2B5E5F0287D6C19ECC31B4504A9F8BE25DA78FA4EF345F91D339B73CC2D70B3904E11CA570CE9B5DC4B08B3C44B74DC463587EA637EF4456E61462B72042FC2F4AD5510A9850C06DC9A7374412FCADDA955BD9800F9754CB3B8CC62D0E98D8282180971055B457C06F351E61164FC5A9DE9D83D1D1378964001380B5B99EE4C5C7D50AC2462A4B7EA34FD32D90BD8D4B46410263673F900D1C60470165DF9F3CB48016AB8CA45CE6875A71D977915CA8251B50258748DBC37FE332EDC2855";
    // skyauth3/Debug/log.txt:349, Server AES Reply (285 bytes).
    private const string HistoricalReply =
        "41020001E8200002014104003A02003C" +
        "000424840200000001848D27205DE56E" +
        "15207DD86A5A16CCBC618B47114C9C37" +
        "E33C562A9F013E0FDF3597B9CEAF928D" +
        "B17A46B5ED1D0F2A035BB7B86E1290D2" +
        "26FCD6F33192F0AAA5787AB82501584D" +
        "70FE59800406A3EA0C53AB15F9533627" +
        "490C841E4D48927E5843549AD5688DF1" +
        "BF36E2ABFE206FB3AB77D9B9AB6BE051" +
        "5AD016DA09B56ACFD293D39A7CB3FAD6" +
        "0017C60143E8A7B2D2B556B37DB6181E" +
        "C47B69F0525096BB8C47F0D2C42B53CE" +
        "D469A687836B3C5A25F2DA0253A657C7" +
        "A677B49F38C155F0BC5957BAF127C25A" +
        "6DCF05B2AC11D64FBA6A173166C6E3F3" +
        "0AF72460EDD6BD15E4118A6F498B5255" +
        "1166D0D07A249C1205E7124990105A0F" +
        "D9C5CABFF6A461BA4205324100";

    internal static void Run(CommunityKeys keys, RSAParameters authority)
    {
        byte[] reply = Hex(HistoricalReply);
        Check(reply.Length == 285, "historical response size");
        byte[] credential = ExtractCredential(reply);
        Check(Equal(NativeCredentials.SuccessPayload(credential), reply), "byte-exact historical envelope encoding");
        RSAParameters historical = new RSAParameters { Modulus = Hex(HistoricalAuthority), Exponent = new byte[] { 1, 0, 1 } };
        List<SkypeField> fields = NativeCredentials.Recover(credential, historical);
        Check(SkypeBlobCodec.Required(fields, 0, 4).Number == 24046449, "independent historical signature expiry");
        Check(SkypeBlobCodec.Required(fields, 3, 0).Bytes.Length == 14, "historical username length");
        Check(SkypeBlobCodec.Required(fields, 4, 1).Bytes.Length == 128, "historical public client key");
        Check(SkypeBlobCodec.Required(SkypeBlobCodec.Required(fields, 5, 2).Children, 0, 9).Number == 24530289,
            "historical opaque timestamp");
        byte[] encoded = SkypeBlobCodec.Encode(fields);
        Check(encoded.Length == 170, "historical credential payload length");
        byte[] signature = new byte[256]; Buffer.BlockCopy(credential, 4, signature, 0, 256);
        Check(Equal(NativeCredentials.EncodeRecoveredBlock(encoded), CommunityKeys.PublicOperation(signature, historical)),
            "byte-exact historical recovery block encoding");
        byte[] damaged = (byte[])credential.Clone(); damaged[30] ^= 1;
        Reject(delegate { NativeCredentials.Recover(damaged, historical); }, "changed historical signature");
        damaged[3] = 2;
        Reject(delegate { NativeCredentials.Recover(damaged, historical); }, "unknown authority ID");
        Reject(delegate { NativeCredentials.Recover(credential, authority); }, "wrong authority key");

        foreach (int length in new[] { 1, 2, 170, 233, 234 })
        {
            byte[] data = new byte[length]; for (int i = 0; i < length; i++) data[i] = (byte)i;
            byte[] block = NativeCredentials.EncodeRecoveredBlock(data);
            Check(Equal(NativeCredentials.DecodeRecoveredBlock(block), data), "recovery boundary " + length);
            foreach (int at in new[] { 0, 235, 255 })
            {
                byte[] bad = (byte[])block.Clone(); bad[at] ^= 1;
                Reject(delegate { NativeCredentials.DecodeRecoveredBlock(bad); }, "bad recovery marker/hash " + at);
            }
        }
        byte[] badPadding = NativeCredentials.EncodeRecoveredBlock(new byte[170]); badPadding[1] = 0;
        Reject(delegate { NativeCredentials.DecodeRecoveredBlock(badPadding); }, "malformed BB padding");
        Reject(delegate { NativeCredentials.EncodeRecoveredBlock(new byte[235]); }, "oversize recovery payload");
        Reject(delegate { NativeCredentials.EncodeRecoveredBlock(new byte[0]); }, "empty recovery payload");
        Reject(delegate { NativeCredentials.DecodeRecoveredBlock(new byte[255]); }, "short recovery block");

        byte[] clientKey = new byte[128]; clientKey[0] = 0x91; clientKey[127] = 3;
        DateTime now = new DateTime(2026, 9, 7, 12, 34, 0, DateTimeKind.Utc);
        byte[] issued = NativeCredentials.Issue(keys, "native.test", clientKey, now);
        CheckIssued(issued, authority, "native.test", clientKey, now);
        Check(!Equal(issued, NativeCredentials.Issue(keys, "another.test", clientKey, now)), "signature binds identity");
        Reject(delegate { NativeCredentials.Issue(keys, "bad\0name", clientKey, now); }, "credential NUL name");
        Reject(delegate { NativeCredentials.Issue(keys, new string('x', 128), clientKey, now); }, "no silent username truncation");
        Reject(delegate { NativeCredentials.Issue(keys, "x", new byte[128], now); }, "invalid modulus");
        Reject(delegate { NativeCredentials.Issue(keys, "x", clientKey, DateTime.SpecifyKind(now, DateTimeKind.Local)); }, "non-UTC timestamp");
        byte[] aes = new byte[32];
        CheckResponse(NativeCredentials.ProtectResponse(NativeCredentials.SuccessPayload(issued), aes), aes,
            authority, "native.test", clientKey, now);
        CheckBlobEncoder();
        Console.WriteLine("PASS native credentials: historical signature and byte-exact envelope, community issuance, RSA recovery guards, AES/CRC response, blob encoding. Original Skype acceptance remains unverified.");
    }

    internal static void CheckResponse(byte[] record, byte[] aes, RSAParameters authority, string username, byte[] clientKey, DateTime now)
    {
        Check(record.Length == 292 && record[0] == 0x17 && record[1] == 3 && record[2] == 1 &&
            ((record[3] << 8) | record[4]) == record.Length - 5, "native response framing");
        byte[] cipher = new byte[record.Length - 7]; Buffer.BlockCopy(record, 5, cipher, 0, cipher.Length);
        uint crc = NativeLoginRequest.Crc(cipher, cipher.Length);
        Check(record[record.Length - 2] == (byte)crc && record[record.Length - 1] == (byte)(crc >> 8), "native response ciphertext CRC");
        byte[] clear = CommunityKeys.LoginAesCtr(aes, cipher, 1);
        CheckIssued(ExtractCredential(clear), authority, username, clientKey, now);
    }

    private static void CheckIssued(byte[] credential, RSAParameters authority, string username, byte[] clientKey, DateTime now)
    {
        List<SkypeField> fields = NativeCredentials.Recover(credential, authority);
        Check(Encoding.UTF8.GetString(SkypeBlobCodec.Required(fields, 3, 0).Bytes) == username, "signed username binding");
        Check(Equal(SkypeBlobCodec.Required(fields, 4, 1).Bytes, clientKey), "signed public-key binding");
        Check(SkypeBlobCodec.Required(fields, 0, 3).Number == 0, "historical credential flags");
        DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        long expected = (long)(now.AddDays(30) - epoch).TotalMinutes;
        Check(Math.Abs((long)SkypeBlobCodec.Required(fields, 0, 4).Number - expected) <= 1, "credential expiry");
        uint opaque = SkypeBlobCodec.Required(SkypeBlobCodec.Required(fields, 5, 2).Children, 0, 9).Number;
        Check(Math.Abs((long)opaque - (long)(now.AddDays(365) - epoch).TotalMinutes) <= 1, "opaque date compatibility hypothesis");
    }

    private static byte[] ExtractCredential(byte[] payload)
    {
        int used;
        List<SkypeField> header = SkypeBlobCodec.Decode(payload, out used);
        Check(header.Count == 2 && SkypeBlobCodec.Required(header, 0, 1).Number == 0x1068 &&
            SkypeBlobCodec.Required(header, 0, 2).Number == 1, "native reply header fields");
        byte[] remainder = new byte[payload.Length - used]; Buffer.BlockCopy(payload, used, remainder, 0, remainder.Length);
        List<SkypeField> body = SkypeBlobCodec.Decode(remainder, out used);
        Check(used == remainder.Length && body.Count == 4, "native reply body consumption");
        Check(SkypeBlobCodec.Required(body, 0, 0x3a).Number == 2 && SkypeBlobCodec.Required(body, 0, 0x3c).Number == 0,
            "native success body values");
        Check(SkypeBlobCodec.Required(body, 5, 0x32).Children.Count == 0, "observed empty response extension");
        return SkypeBlobCodec.Required(body, 4, 0x24).Bytes;
    }

    private static void CheckBlobEncoder()
    {
        List<SkypeField> fields = new List<SkypeField> {
            new SkypeField { Type = 0, Id = UInt32.MaxValue, Number = UInt32.MaxValue },
            new SkypeField { Type = 1, Id = 1, Bytes = new byte[8] },
            new SkypeField { Type = 2, Id = 2, Bytes = new byte[6] },
            new SkypeField { Type = 3, Id = 3, Bytes = Encoding.UTF8.GetBytes("test") },
            new SkypeField { Type = 4, Id = 4, Bytes = new byte[300] },
            new SkypeField { Type = 5, Id = 5, Children = new List<SkypeField>() },
            new SkypeField { Type = 6, Id = 6, Bytes = new byte[] { 0,0,0,0, 255,255,255,255 } }
        };
        byte[] encoded = SkypeBlobCodec.Encode(fields); int used;
        List<SkypeField> decoded = SkypeBlobCodec.Decode(encoded, out used);
        Check(used == encoded.Length && Equal(SkypeBlobCodec.Encode(decoded), encoded), "all blob types round trip");
        fields[3].Bytes = new byte[] { 65, 0 };
        Reject(delegate { SkypeBlobCodec.Encode(fields); }, "encoder embedded NUL");
        fields[3].Bytes = new byte[0]; fields[4].Bytes = new byte[16384];
        Reject(delegate { SkypeBlobCodec.Encode(fields); }, "encoder output bound");
        fields[4].Bytes = new byte[0]; fields[5].Children = fields;
        Reject(delegate { SkypeBlobCodec.Encode(fields); }, "encoder recursion bound");
    }

    private static byte[] Hex(string text)
    {
        byte[] bytes = new byte[text.Length / 2];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(text.Substring(2 * i, 2), 16);
        return bytes;
    }
    private static bool Equal(byte[] a, byte[] b) { return Convert.ToBase64String(a) == Convert.ToBase64String(b); }
    private static void Check(bool value, string label) { if (!value) throw new Exception("Failed: " + label); }
    private static void Reject(Action action, string label)
    {
        try { action(); }
        catch (InvalidDataException) { return; }
        catch (CryptographicException) { return; }
        catch (ArgumentException) { return; }
        throw new Exception("Expected rejection: " + label);
    }
}
