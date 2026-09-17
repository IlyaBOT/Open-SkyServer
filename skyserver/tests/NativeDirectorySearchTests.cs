using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using SkyServer;

internal static class NativeDirectorySearchTests
{
    internal static void Run(SkyDatabase db, CommunityKeys keys, byte[] exchange, byte[] digest, byte[] material)
    {
        db.SetAccountEmail("transport.test", "directory@example.test");
        Check(Find(db, 0, 0, "TRANSPORT.TEST").Count == 1, "case-insensitive username lookup");
        Check(Find(db, 1, 0, "DIRECTORY@example.test").Count == 1, "exact profile email lookup");
        Check(Find(db, 2, 8, "sport Te").Count == 1, "display name substring");
        Check(Find(db, 0, 5, "trans").Count == 1, "username prefix");
        Check(Find(db, 0, 0, "absent.test").Count == 0, "absent user");
        Check(Find(db, 0, 0, "x' OR 1=1 --").Count == 0, "SQL quote is literal");
        Check(Find(db, 0, 8, "%").Count == 0 && Find(db, 0, 8, "_").Count == 0, "wildcards are literal");
        Reject(delegate { Find(db, 1, 8, "@example.test"); }, "email enumeration");
        Reject(delegate { Find(db, 7, 0, "London"); }, "unsupported filters cannot broaden search");
        Reject(delegate { Find(db, 0, 0, ""); }, "empty query");
        Reject(delegate { Find(db, 0, 0, "name\n"); }, "control character");
        Reject(delegate { db.SearchNativeDirectory(new List<NativeDirectoryTerm>()); }, "unfiltered directory dump");
        List<SkypeField> metadata = Query(0, 0, "transport.test");
        byte[] expected = NativeDirectorySearch.Respond(new NativeLoginRequest {
            Username = "native.test", Operation = 0x4278, RequestId = 9, Metadata = metadata }, db);
        int consumed;
        List<SkypeField> header = SkypeBlobCodec.Decode(expected, out consumed);
        Check(SkypeBlobCodec.Required(header, 0, 1).Number == 0x81b0, "native search completion status");
        Check(SkypeBlobCodec.Required(header, 0, 2).Number == 9, "search request correlation");
        byte[] body = new byte[expected.Length - consumed];
        Buffer.BlockCopy(expected, consumed, body, 0, body.Length);
        List<SkypeField> results = SkypeBlobCodec.Decode(body, out consumed);
        Check(consumed == body.Length && results.Count == 1, "one native result record");
        List<SkypeField> row = SkypeBlobCodec.Required(results, 5, 0x64).Children;
        Check(row.Count == 2, "no private profile or credential data in search results");
        Check(Encoding.UTF8.GetString(SkypeBlobCodec.Required(row, 3, 0x66).Bytes) == "transport.test", "native result identity");
        Check(Encoding.UTF8.GetString(SkypeBlobCodec.Required(row, 3, 0x65).Bytes) == "Transport Test", "native result display name");
        ProtocolTests.RunCommunityTransport("native directory RSA/AES transport", keys, exchange,
            NativeContactSyncTests.Request(digest, material, 0x4278, metadata), null, expected.Length + 7, delegate(byte[] response) {
                byte[] cipher = new byte[response.Length - 7];
                Buffer.BlockCopy(response, 5, cipher, 0, cipher.Length);
                uint crc = NativeLoginRequest.Crc(cipher, cipher.Length);
                Check(response[response.Length-2] == (byte)crc && response[response.Length-1] == (byte)(crc >> 8), "search response CRC");
                byte[] clear = CommunityKeys.LoginAesCtr(CommunityKeys.DeriveLoginAesKey(material), cipher, 1);
                Check(Convert.ToBase64String(clear) == Convert.ToBase64String(expected), "encrypted directory result");
            });
        ProtocolTests.RunCommunityTransport("native directory rejects wrong password", keys, exchange,
            NativeContactSyncTests.Request(new byte[16], material, 0x4278, metadata), null);
        List<SkypeField> invalid = Query(0, 0, "transport.test");
        invalid[0].Children.Add(new SkypeField { Type = 0, Id = 0x21, Number = 2 });
        Reject(delegate { NativeDirectorySearch.Respond(new NativeLoginRequest { Operation = 0x4278, Metadata = invalid }, db); }, "ambiguous term");
        MethodInfo execute = typeof(SkyDatabase).GetMethod("Execute", BindingFlags.NonPublic | BindingFlags.Instance);
        execute.Invoke(db, new object[] { "UPDATE accounts SET is_active=0 WHERE login='transport.test';" });
        try { Check(Find(db, 0, 0, "transport.test").Count == 0, "disabled accounts are not discoverable"); }
        finally { execute.Invoke(db, new object[] { "UPDATE accounts SET is_active=1 WHERE login='transport.test';" }); }
        Check(db.GetContacts("native.test").Count == 0, "search does not add contacts or grant authorization");
        Console.WriteLine("PASS native directory tests: DB lookup, wire fields, password verification, inactive accounts and literal filters. UI acceptance requires a live client search.");
    }

    private static List<Account> Find(SkyDatabase db, uint property, uint comparison, string text)
    {
        return db.SearchNativeDirectory(new List<NativeDirectoryTerm> {
            new NativeDirectoryTerm { Property = property, Comparison = comparison, Text = text } });
    }
    private static List<SkypeField> Query(uint property, uint comparison, string text)
    {
        return new List<SkypeField> {
            new SkypeField { Type = 5, Id = 0x20, Children = new List<SkypeField> {
                new SkypeField { Type = 0, Id = 0x21, Number = property },
                new SkypeField { Type = 0, Id = 0x22, Number = comparison },
                new SkypeField { Type = 3, Id = 0x23, Bytes = Encoding.UTF8.GetBytes(text) }
            } }, new SkypeField { Type = 0, Id = 0x24, Number = 1 }
        };
    }
    private static void Check(bool condition, string label) { if (!condition) throw new Exception("FAIL " + label); }
    private static void Reject(Action action, string label)
    {
        try { action(); } catch (InvalidDataException) { return; }
        throw new Exception("Accepted " + label);
    }
}
