using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using SkyServer;

internal static class NativeContactSyncTests
{
    internal static void Run(SkyDatabase database, CommunityKeys keys, byte[] exchange, byte[] digest, byte[] material)
    {
        NativeDirectorySearchTests.Run(database, keys, exchange, digest, material);
        byte[] content = Encoding.ASCII.GetBytes("123456789");
        uint checksum = NativeLoginRequest.Crc(content, content.Length);
        Check(checksum == 0x340bc6d9, "uncomplemented CRC fixture");
        NativeDocumentSnapshot empty = database.GetNativeDocuments("native.test");
        Check(empty.Revision == 1 && empty.Documents.Count == 0, "empty persisted namespace");
        database.AddContact("native.test", "transport.test");
        AssertTransport(database, keys, exchange, digest, material, 0x1792, new List<SkypeField> { Number(7, 1) }, delegate(List<SkypeField> body) {
            Check(body.Count == 1, "contact list contains only this owner's DB contacts");
            List<SkypeField> contact = SkypeBlobCodec.Required(body, 5, 0x39).Children;
            Check(SkypeBlobCodec.Required(contact, 0, 1).Number == 0, "Skype contact type");
            Check(Encoding.UTF8.GetString(SkypeBlobCodec.Required(contact, 3, 2).Bytes) == "transport.test", "contact name from database");
        });
        Reject(delegate { NativeContactSync.Respond(new NativeLoginRequest { Username = "native.test", Operation = 0x1792,
            RequestId = 9, Metadata = new List<SkypeField> { Number(7, 2) } }, database); }, "unknown contact collection");
        ProtocolTests.RunCommunityTransport("legacy contact download rejects wrong password", keys, exchange,
            Request(new byte[16], material, 0x1792, new List<SkypeField> { Number(7, 1) }), null);
        database.RemoveNativeDocument("native.test", "u/transport.test");
        AssertTransport(database, keys, exchange, digest, material, 0x178c, Fields(), delegate(List<SkypeField> body) {
            Check(SkypeBlobCodec.Required(body, 0, 0x36).Number == 1, "initial manifest revision");
            Check(SkypeBlobCodec.Required(body, 4, 0x35).Bytes.Length == 0, "empty manifest");
        });
        List<SkypeField> upload = Fields(Number(0x32, checksum), Bytes(3, 0x34, Encoding.UTF8.GetBytes("contact's record")), Bytes(4, 0x33, content));
        AssertTransport(database, keys, exchange, digest, material, 0x1789, upload, delegate(List<SkypeField> body) {
            Check(SkypeBlobCodec.Required(body, 0, 0x36).Number == 2, "upload committed revision");
        });
        NativeDocumentSnapshot stored = database.GetNativeDocuments("native.test");
        Check(stored.Documents.Count == 1 && stored.Documents[0].Name == "contact's record" && Equal(stored.Documents[0].Body, content), "upload persisted exact bytes and quoted name");
        Check(database.PutNativeDocument("native.test", "contact's record", content, checksum) == 2, "retry is idempotent");
        AssertTransport(database, keys, exchange, digest, material, 0x178c, Fields(), delegate(List<SkypeField> body) {
            Check(Equal(SkypeBlobCodec.Required(body, 4, 0x35).Bytes, new byte[] { 0x34, 0x0b, 0xc6, 0xd9 }), "manifest big endian checksum");
        });
        AssertTransport(database, keys, exchange, digest, material, 0x1788, Fields(Number(0x32, checksum)), delegate(List<SkypeField> body) {
            List<SkypeField> record = SkypeBlobCodec.Required(body, 5, 0x37).Children;
            Check(Encoding.UTF8.GetString(SkypeBlobCodec.Required(record, 3, 0x34).Bytes) == "contact's record", "download name");
            Check(Equal(SkypeBlobCodec.Required(record, 4, 0x33).Bytes, content), "download content");
        });
        Check(database.GetNativeDocuments("transport.test").Documents.Count == 0, "account namespaces are isolated");
        Reject(delegate { NativeContactSync.Respond(new NativeLoginRequest { Username = "transport.test", Operation = 0x1788,
            RequestId = 9, Metadata = Fields(Number(0x32, checksum)) }, database); }, "cross-account document lookup");
        byte[] badDigest = new byte[16];
        ProtocolTests.RunCommunityTransport("native document upload rejects wrong password", keys, exchange,
            Request(badDigest, material, 0x1789, upload), null);
        Reject(delegate { database.PutNativeDocument("native.test", "bad", content, checksum ^ 1); }, "bad checksum rejected");
        Reject(delegate { database.PutNativeDocument("native.test", "other", content, checksum); }, "ambiguous checksum rejected");
        Reject(delegate { database.PutNativeDocument("native.test", "bad\tname", content, checksum); }, "control characters rejected");
        Reject(delegate { NativeContactSync.Respond(new NativeLoginRequest { Username = "native.test", Operation = 0x178c,
            RequestId = 9, Metadata = new List<SkypeField>() }, database); }, "missing instance identifier");
        Check(database.GetNativeDocuments("native.test").Revision == 2, "invalid mutations do not advance version");
        byte[] updated = Encoding.ASCII.GetBytes("changed");
        uint updatedChecksum = NativeLoginRequest.Crc(updated, updated.Length);
        Check(database.PutNativeDocument("native.test", "contact's record", updated, updatedChecksum) == 3, "update advances version");
        MethodInfo execute = typeof(SkyDatabase).GetMethod("Execute", BindingFlags.Instance | BindingFlags.NonPublic);
        execute.Invoke(database, new object[] { "UPDATE native_document_versions SET revision=4294967295 WHERE login='native.test';" });
        Reject(delegate { database.PutNativeDocument("native.test", "contact's record", content, checksum); }, "revision overflow aborts transaction");
        NativeDocumentSnapshot failed = database.GetNativeDocuments("native.test");
        Check(failed.Revision == UInt32.MaxValue && Equal(failed.Documents[0].Body, updated), "SQL failure cannot commit document after failed version update");
        execute.Invoke(database, new object[] { "UPDATE native_document_versions SET revision=3 WHERE login='native.test';" });
        string dbPath = (string)typeof(SkyDatabase).GetField("dbPath", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(database);
        string sqlite = (string)typeof(SkyDatabase).GetField("sqlitePath", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(database);
        NativeDocumentSnapshot reopened = new SkyDatabase(dbPath, sqlite).GetNativeDocuments("native.test");
        Check(reopened.Revision == 3 && Equal(reopened.Documents[0].Body, updated), "documents survive reopening database");
        List<SkypeField> deletion = Fields(Bytes(3, 0x34, Encoding.UTF8.GetBytes("contact's record")));
        ProtocolTests.RunCommunityTransport("native document deletion rejects wrong password", keys, exchange,
            Request(new byte[16], material, 0x178a, deletion), null);
        Check(database.RemoveNativeDocument("transport.test", "contact's record") == 1, "delete is confined to authenticated account");
        Check(database.GetNativeDocuments("native.test").Documents.Count == 1, "cross-account delete leaves original intact");
        AssertTransport(database, keys, exchange, digest, material, 0x178a, deletion, delegate(List<SkypeField> body) {
            Check(SkypeBlobCodec.Required(body, 0, 0x36).Number == 4, "delete acknowledges committed revision");
        });
        Check(database.GetNativeDocuments("native.test").Documents.Count == 0, "delete persisted");
        Check(database.RemoveNativeDocument("native.test", "contact's record") == 4, "delete retry is idempotent");
        database.PutNativeDocument("native.test", "cascade", updated, updatedChecksum);
        database.AddContact("native.test", "transport.test");
        database.EnsureNativeContactDocuments("native.test");
        NativeDocumentSnapshot projected = database.GetNativeDocuments("native.test");
        NativeDocument peer = projected.Documents.Find(delegate(NativeDocument d) { return d.Name == "u/transport.test"; });
        Check(peer != null, "DB contacts projected into native records");
        int consumed;
        List<SkypeField> peerFields = SkypeBlobCodec.Decode(peer.Body, out consumed);
        Check(consumed == peer.Body.Length && Encoding.UTF8.GetString(SkypeBlobCodec.Required(peerFields, 3, 0x10).Bytes) == "transport.test", "projected native identity");
        Check(!peerFields.Exists(delegate(SkypeField f) { return f.Id == 0x7d; }), "projection does not forge remote authorization");
        database.EnsureNativeContactDocuments("native.test");
        Check(database.GetNativeDocuments("native.test").Revision == projected.Revision, "projection is idempotent");
        database.RemoveNativeDocument("native.test", "u/transport.test");
        database.EnsureNativeContactDocuments("native.test");
        Check(database.GetContacts("native.test").Count == 0 && !database.GetNativeDocuments("native.test").Documents.Exists(delegate(NativeDocument d) { return d.Name == "u/transport.test"; }), "deleted contacts are not resurrected by migration");
        Console.WriteLine("PASS native document tests: authenticated manifest/upload/download, exact persistence, isolation, retry, CRC and transaction failure. Native UI acceptance still requires live verification.");
    }

    private static void AssertTransport(SkyDatabase db, CommunityKeys keys, byte[] exchange, byte[] digest, byte[] material,
        uint operation, List<SkypeField> fields, Action<List<SkypeField>> inspect)
    {
        byte[] expected;
        // Predict the envelope size without pre-executing a mutating RPC.
        if (operation == 0x1789 || operation == 0x178a)
            expected = NativeCredentials.AccountResponse(SkypeBlobCodec.Encode(new List<SkypeField> { Number(0x36, operation == 0x1789 ? 2U : 4U) }), 9, 0x1450);
        else expected = NativeContactSync.Respond(new NativeLoginRequest { Username = "native.test", Operation = operation, RequestId = 9, Metadata = fields }, db);
        ProtocolTests.RunCommunityTransport("native document RPC 0x" + operation.ToString("X"), keys, exchange,
            Request(digest, material, operation, fields), null, expected.Length + 7, delegate(byte[] response) {
                byte[] cipher = new byte[response.Length - 7];
                Buffer.BlockCopy(response, 5, cipher, 0, cipher.Length);
                uint crc = NativeLoginRequest.Crc(cipher, cipher.Length);
                Check(response[response.Length - 2] == (byte)crc && response[response.Length - 1] == (byte)(crc >> 8), "response CRC");
                byte[] clear = CommunityKeys.LoginAesCtr(CommunityKeys.DeriveLoginAesKey(material), cipher, 1);
                int consumed;
                List<SkypeField> header = SkypeBlobCodec.Decode(clear, out consumed);
                Check(SkypeBlobCodec.Required(header, 0, 1).Number == 0x1450 && SkypeBlobCodec.Required(header, 0, 2).Number == 9, "RPC header");
                byte[] body = new byte[clear.Length - consumed];
                Buffer.BlockCopy(clear, consumed, body, 0, body.Length);
                List<SkypeField> decoded = SkypeBlobCodec.Decode(body, out consumed);
                Check(consumed == body.Length, "response fully consumed");
                inspect(decoded);
            });
    }

    internal static byte[] Request(byte[] digest, byte[] material, uint operation, List<SkypeField> fields)
    {
        byte[] account = SkypeBlobCodec.Encode(new List<SkypeField> { Number(0, operation), Number(2, 9),
            Bytes(3, 4, Encoding.UTF8.GetBytes("native.test")), Bytes(4, 5, digest) });
        byte[] metadata = SkypeBlobCodec.Encode(fields);
        byte[] clear = new byte[account.Length + metadata.Length];
        Buffer.BlockCopy(account, 0, clear, 0, account.Length);
        Buffer.BlockCopy(metadata, 0, clear, account.Length, metadata.Length);
        byte[] cipher = CommunityKeys.LoginAesCtr(CommunityKeys.DeriveLoginAesKey(material), clear, 0);
        byte[] record = new byte[cipher.Length + 7];
        record[0] = 0x17; record[1] = 3; record[2] = 1;
        record[3] = (byte)((cipher.Length + 2) >> 8); record[4] = (byte)(cipher.Length + 2);
        Buffer.BlockCopy(cipher, 0, record, 5, cipher.Length);
        uint crc = NativeLoginRequest.Crc(cipher, cipher.Length);
        record[record.Length - 2] = (byte)crc; record[record.Length - 1] = (byte)(crc >> 8);
        return record;
    }
    private static List<SkypeField> Fields(params SkypeField[] extra)
    {
        List<SkypeField> fields = new List<SkypeField> { Bytes(1, 0x3a, new byte[8]) };
        fields.AddRange(extra);
        return fields;
    }
    private static SkypeField Number(uint id, uint value) { return new SkypeField { Type = 0, Id = id, Number = value }; }
    private static SkypeField Bytes(byte type, uint id, byte[] value) { return new SkypeField { Type = type, Id = id, Bytes = value }; }
    private static bool Equal(byte[] a, byte[] b) { return Convert.ToBase64String(a) == Convert.ToBase64String(b); }
    private static void Check(bool condition, string label) { if (!condition) throw new Exception("FAIL " + label); }
    private static void Reject(Action action, string label)
    {
        try { action(); } catch (InvalidDataException) { return; } catch (InvalidOperationException) { return; }
        throw new Exception("Accepted " + label);
    }
}
