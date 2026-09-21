using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SkyServer;

internal static class NativeSignedRecordTests
{
    internal static void Run(CommunityKeys keys)
    {
        DateTime now = new DateTime(2026, 9, 20, 0, 0, 0, DateTimeKind.Utc);
        using (RSACryptoServiceProvider client = new RSACryptoServiceProvider(1024))
        {
            client.PersistKeyInCsp = false;
            RSAParameters key = client.ExportParameters(true);
            byte[] credential = NativeCredentials.Issue(keys, "signed-record.test", key.Modulus, now);
            foreach (int size in new[] { 0, 81, 82, 300 })
            {
                byte[] payload = SkypeBlobCodec.Encode(new List<SkypeField> {
                    new SkypeField { Type = 4, Id = 3, Bytes = new byte[size] }
                });
                byte[] value = Sign(credential, payload, key, false);
                NativeRecordDirectory directory = new NativeRecordDirectory(keys);
                SkypeNodeCommand query = new SkypeNodeCommand { Code = 0xe, Flags = 2, RequestId = 123,
                    Fields = new List<SkypeField> {
                        new SkypeField { Type = 5, Id = 0, Children = new List<SkypeField> {
                            new SkypeField { Type = 3, Id = 0, Bytes = Encoding.UTF8.GetBytes("signed-record.test") },
                            new SkypeField { Type = 0, Id = 1, Number = 0 },
                            new SkypeField { Type = 0, Id = 2, Number = 16 } } },
                        new SkypeField { Type = 6, Id = 1, Bytes = new byte[] {16,0,0,0,11,0,0,0} }
                    } };
                if (directory.Handle(query, now).Fields.Count != 1) throw new Exception("Invented location record");
                SkypeNodeCommand publication = new SkypeNodeCommand { Code = 0xc, Flags = 2, RequestId = 124,
                    Fields = new List<SkypeField> { new SkypeField { Type = 4, Id = 0xb, Bytes = value } } };
                SkypeNodeCommand stored = directory.Handle(publication, now);
                if (stored.Code != 0xd || stored.RequestId != 124) throw new Exception("Publication correlation lost");
                SkypeNodeCommand found = directory.Handle(query, now);
                if (found.Code != 0xf || found.RequestId != 123 || found.Fields.Count != 2)
                    throw new Exception("Location lookup failed");
                byte[] returned = SkypeBlobCodec.Required(SkypeBlobCodec.Required(found.Fields, 5, 0).Children, 4, 0xb).Bytes;
                if (Convert.ToBase64String(returned) != Convert.ToBase64String(value)) throw new Exception("Signed record altered");
                uint recordId = SkypeBlobCodec.Required(SkypeBlobCodec.Required(found.Fields, 5, 0).Children, 0, 0x10).Number;
                query.Fields.Add(new SkypeField { Type = 6, Id = 2, Bytes = BitConverter.GetBytes(recordId) });
                if (directory.Handle(query, now).Fields.Count != 1) throw new Exception("Excluded location returned again");
                query.Fields.RemoveAt(2);
                query.Fields[0].Children[0].Bytes = Encoding.UTF8.GetBytes("different-record.test");
                if (directory.Handle(query, now).Fields.Count != 1) throw new Exception("Unrelated location returned");
                query.Fields[0].Children[0].Bytes = Encoding.UTF8.GetBytes("signed-record.test");
                if (directory.Handle(query, now.AddMinutes(2)).Fields.Count != 1) throw new Exception("Stale location retained");
                NativeSignedRecord record = NativeSignedRecord.Verify(value, keys, now);
                if (record.Username != "signed-record.test" || SkypeBlobCodec.Required(record.Fields, 4, 3).Bytes.Length != size)
                    throw new Exception("Signed record recovery failed");
                foreach (int index in new[] { 0, 8, 264, value.Length - 1 })
                {
                    byte[] bad = (byte[])value.Clone();
                    bad[index] ^= 1;
                    Reject(delegate { NativeSignedRecord.Verify(bad, keys, now); }, "modified record");
                }
                Reject(delegate { NativeSignedRecord.Verify(value, keys, now.AddDays(31)); }, "expired credential");
                byte[] wrongBinding = Sign(credential, payload, key, true);
                Reject(delegate { NativeSignedRecord.Verify(wrongBinding, keys, now); }, "valid signature with wrong credential binding");
            }
            byte[] trailing = Sign(credential, new byte[] { 0x41, 0, 0 }, key, false);
            Reject(delegate { NativeSignedRecord.Verify(trailing, keys, now); }, "trailing fields");
            Reject(delegate { NativeSignedRecord.Verify(new byte[391], keys, now); }, "short envelope");
            Reject(delegate { NativeSignedRecord.Verify(new byte[8193], keys, now); }, "oversized envelope");
        }
        Console.WriteLine("PASS signed directory records: full/partial recovery, authority/client signatures, credential binding, expiry, tampering and bounds");
    }

    private static byte[] Sign(byte[] credential, byte[] payload, RSAParameters key, bool wrongBinding)
    {
        byte[] message = new byte[20 + payload.Length];
        byte[] block = new byte[128];
        int recovered = Math.Min(message.Length, 106);
        int start = 107 - recovered;
        using (SHA1 sha = SHA1.Create())
        {
            Buffer.BlockCopy(sha.ComputeHash(credential), 0, message, 0, 20);
            if (wrongBinding) message[0] ^= 1;
            Buffer.BlockCopy(payload, 0, message, 20, payload.Length);
            Buffer.BlockCopy(sha.ComputeHash(message), 0, block, 107, 20);
        }
        block[0] = message.Length > 106 ? (byte)0x6a : start == 1 ? (byte)0x4a : (byte)0x4b;
        if (start > 1)
        {
            for (int i = 1; i < start - 1; i++) block[i] = 0xbb;
            block[start - 1] = 0xba;
        }
        Buffer.BlockCopy(message, 0, block, start, recovered);
        block[127] = 0xbc;
        byte[] little = BigInteger.ModPow(Big(block), Big(key.D), Big(key.Modulus)).ToByteArray();
        byte[] result = new byte[392 + message.Length - recovered];
        result[2] = 1; result[3] = 4;
        Buffer.BlockCopy(credential, 0, result, 4, 260);
        for (int i = 0; i < Math.Min(128, little.Length); i++) result[391 - i] = little[i];
        Buffer.BlockCopy(message, recovered, result, 392, message.Length - recovered);
        return result;
    }

    private static BigInteger Big(byte[] big)
    {
        byte[] little = new byte[big.Length + 1];
        for (int i = 0; i < big.Length; i++) little[i] = big[big.Length - i - 1];
        return new BigInteger(little);
    }

    private static void Reject(Action action, string label)
    {
        try { action(); }
        catch (CryptographicException) { return; }
        catch (InvalidDataException) { return; }
        throw new Exception("Accepted " + label);
    }
}
