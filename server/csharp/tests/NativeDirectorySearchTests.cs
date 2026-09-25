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
        Check(Find(db, 2, 0, "Transport Test").Count == 1, "exact display name");
        Check(Find(db, 0, 5, "trans").Count == 1, "username prefix");
        Check(Find(db, 0, 0, "absent.test").Count == 0, "absent user");
        Check(Find(db, 0, 0, "x' OR 1=1 --").Count == 0, "SQL quote is literal");
        Check(Find(db, 0, 5, "%").Count == 0 && Find(db, 0, 5, "_").Count == 0, "wildcards are literal");
        Check(Find(db, 1, 8, "DIRECTORY@example.test").Count == 1, "native email CW matches the complete stored address");
        Check(Find(db, 1, 8, "@example.test").Count == 0 && Find(db, 1, 8, "directory").Count == 0, "CW does not enumerate partial emails");
        Check(Find(db, 2, 8, "test transport").Count == 1, "name CW matches whole words");
        Check(Find(db, 2, 8, "sport Te").Count == 0, "CW is not substring matching");
        Check(Find(db, 2, 9, "te tran").Count == 1, "name CP matches word prefixes in any order");
        Check(Find(db, 2, 9, "sport").Count == 0, "CP does not match inside a word");
        Check(Find(db, 2, 9, "%").Count == 0 && Find(db, 2, 9, "x' OR 1=1 --").Count == 0, "word prefixes are SQL literals");
        Reject(delegate { Find(db, 1, 5, "directory"); }, "unsupported email prefix");
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
        // VA 00641010 + 00646920: the regular UI uses login PQ OR email
        // CW OR full-name CP; exact lookup uses login EQ OR email CW.
        foreach (bool exact in new[] { false, true })
        {
            List<SkypeField> nativeQuery = Query(0, exact ? 0u : 5u, "directory@example.test");
            nativeQuery.Insert(1, Or());
            nativeQuery.Insert(2, Query(1, 8, "directory@example.test")[0]);
            if (!exact)
            {
                nativeQuery.Insert(3, Or());
                nativeQuery.Insert(4, Query(2, 9, "directory@example.test")[0]);
                nativeQuery[nativeQuery.Count - 1].Number = 0;
            }
            byte[] actual = NativeDirectorySearch.Respond(new NativeLoginRequest {
                Operation = 0x4278, RequestId = 9, Metadata = nativeQuery }, db);
            Check(Convert.ToBase64String(actual) == Convert.ToBase64String(expected), "UI alternatives return the email match exactly once");
            ProtocolTests.RunCommunityTransport("native directory UI " + (exact ? "exact" : "general") + " OR transport", keys, exchange,
                NativeContactSyncTests.Request(digest, material, 0x4278, nativeQuery), null, expected.Length + 7, delegate(byte[] response) {
                    byte[] cipher = new byte[response.Length - 7];
                    Buffer.BlockCopy(response, 5, cipher, 0, cipher.Length);
                    byte[] clear = CommunityKeys.LoginAesCtr(CommunityKeys.DeriveLoginAesKey(material), cipher, 1);
                    Check(Convert.ToBase64String(clear) == Convert.ToBase64String(expected), "encrypted UI-shaped directory result");
                });
        }
        Check(db.SearchNativeDirectory(new List<NativeDirectoryTerm> {
            Term(0, 0, "transport.test"), Term(1, 8, "absent@example.test"), Alternative(), Term(2, 9, "te tran")
        }).Count == 1, "AND groups are joined with OR");
        Check(db.SearchNativeDirectory(new List<NativeDirectoryTerm> {
            Term(0, 0, "transport.test"), Term(1, 8, "absent@example.test")
        }).Count == 0, "adjacent filters retain AND semantics");
        Check(db.SearchNativeDirectory(new List<NativeDirectoryTerm> {
            Term(0, 0, "transport.test"), Alternative(), Term(1, 8, "directory@example.test")
        }).Count == 1, "OR alternatives do not duplicate an account");
        foreach (List<NativeDirectoryTerm> invalidTerms in new[] {
            new List<NativeDirectoryTerm> { Alternative() },
            new List<NativeDirectoryTerm> { Alternative(), Term(0, 0, "transport.test") },
            new List<NativeDirectoryTerm> { Term(0, 0, "transport.test"), Alternative() },
            new List<NativeDirectoryTerm> { Term(0, 0, "transport.test"), Alternative(), Alternative(), Term(0, 0, "transport.test") }
        }) Reject(delegate { db.SearchNativeDirectory(invalidTerms); }, "empty logical branch");
        List<NativeDirectoryTerm> tooMany = new List<NativeDirectoryTerm>();
        for (int i = 0; i < 9; i++) tooMany.Add(Term(0, 0, "transport.test"));
        Reject(delegate { db.SearchNativeDirectory(tooMany); }, "more than eight filters");
        foreach (uint badNumber in new uint[] { 1, UInt32.MaxValue })
        {
            List<SkypeField> invalidLogical = Query(0, 0, "transport.test");
            SkypeField separator = Or();
            separator.Children[2].Number = badNumber;
            invalidLogical.Insert(1, separator);
            invalidLogical.Insert(2, Query(1, 8, "directory@example.test")[0]);
            Reject(delegate { NativeDirectorySearch.Respond(new NativeLoginRequest { Operation = 0x4278, Metadata = invalidLogical }, db); }, "unknown logical value");
        }
        List<SkypeField> mistypedLogical = Query(17, 0, "0");
        Reject(delegate { NativeDirectorySearch.Respond(new NativeLoginRequest { Operation = 0x4278, Metadata = mistypedLogical }, db); }, "string logical value");
        List<SkypeField> invalid = Query(0, 0, "transport.test");
        invalid[0].Children.Add(new SkypeField { Type = 0, Id = 0x21, Number = 2 });
        Reject(delegate { NativeDirectorySearch.Respond(new NativeLoginRequest { Operation = 0x4278, Metadata = invalid }, db); }, "ambiguous term");
        MethodInfo execute = typeof(SkyDatabase).GetMethod("Execute", BindingFlags.NonPublic | BindingFlags.Instance);
        execute.Invoke(db, new object[] { "UPDATE accounts SET is_active=0 WHERE login='transport.test';" });
        try
        {
            Check(Find(db, 0, 0, "transport.test").Count == 0, "disabled accounts are not discoverable");
            Check(db.SearchNativeDirectory(new List<NativeDirectoryTerm> {
                Term(0, 0, "absent.test"), Alternative(), Term(1, 8, "directory@example.test")
            }).Count == 0, "OR cannot bypass active-account restriction");
        }
        finally { execute.Invoke(db, new object[] { "UPDATE accounts SET is_active=1 WHERE login='transport.test';" }); }
        Check(db.GetContacts("native.test").Count == 0, "search does not add contacts or grant authorization");
        Console.WriteLine("PASS native directory tests: UI-shaped OR queries, email CW, name words, DB lookup, wire fields, password verification, inactive accounts and literal filters. UI acceptance requires a live client search.");
    }

    private static List<Account> Find(SkyDatabase db, uint property, uint comparison, string text)
    {
        return db.SearchNativeDirectory(new List<NativeDirectoryTerm> {
            new NativeDirectoryTerm { Property = property, Comparison = comparison, Text = text } });
    }
    private static NativeDirectoryTerm Term(uint property, uint comparison, string text)
    {
        return new NativeDirectoryTerm { Property = property, Comparison = comparison, Text = text };
    }
    private static NativeDirectoryTerm Alternative()
    {
        return new NativeDirectoryTerm { Property = 17, Comparison = 0, Number = 0 };
    }
    private static SkypeField Or()
    {
        return new SkypeField { Type = 5, Id = 0x20, Children = new List<SkypeField> {
            new SkypeField { Type = 0, Id = 0x21, Number = 17 },
            new SkypeField { Type = 0, Id = 0x22, Number = 0 },
            new SkypeField { Type = 0, Id = 0x23, Number = 0 }
        } };
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
