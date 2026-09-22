using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SkyServer
{
    internal sealed class NativeDocument
    {
        public string Name;
        public uint Checksum;
        public byte[] Body;
    }

    internal sealed class NativeDocumentSnapshot
    {
        public uint Revision;
        public readonly List<NativeDocument> Documents = new List<NativeDocument>();
    }

    internal static class NativeContactSync
    {
        internal static byte[] Respond(NativeLoginRequest request, SkyDatabase database)
        {
            if (request.Operation == 0x1792)
            {
                if (SkypeBlobCodec.Required(request.Metadata, 0, 7).Number != 1)
                    throw new InvalidDataException("Unknown owner-local contact list");
                List<SkypeField> contacts = new List<SkypeField>();
                foreach (Account contact in database.GetContacts(request.Username))
                {
                    // VA 005A4659 reads 5/39, 0/1=Skype (1=PSTN), 3/2=name.
                    // Leave optional authorization flags and serial at the
                    // client's defaults; a DB contact is not a signed grant.
                    contacts.Add(new SkypeField { Type = 5, Id = 0x39, Children = new List<SkypeField> {
                        new SkypeField { Type = 0, Id = 1, Number = 0 },
                        new SkypeField { Type = 3, Id = 2, Bytes = Encoding.UTF8.GetBytes(contact.Login) }
                    } });
                }
                return NativeCredentials.AccountResponse(SkypeBlobCodec.Encode(contacts), request.RequestId, 0x1450);
            }
            // 4.2 VA 0074EF70 / 0074F5E0: 1/3A identifies the client instance,
            // not an account. Authorization always uses the verified envelope.
            byte[] instance = SkypeBlobCodec.Required(request.Metadata, 1, 0x3a).Bytes;
            if (instance == null || instance.Length != 8) throw new InvalidDataException("Invalid native document client identifier");
            List<SkypeField> body = new List<SkypeField>();
            uint revision;
            if (request.Operation == 0x1789)
            {
                string name = new UTF8Encoding(false, true).GetString(SkypeBlobCodec.Required(request.Metadata, 3, 0x34).Bytes);
                byte[] content = SkypeBlobCodec.Required(request.Metadata, 4, 0x33).Bytes;
                uint checksum = SkypeBlobCodec.Required(request.Metadata, 0, 0x32).Number;
                revision = database.PutNativeDocument(request.Username, name, content, checksum);
            }
            else if (request.Operation == 0x178a)
            {
                string name = new UTF8Encoding(false, true).GetString(SkypeBlobCodec.Required(request.Metadata, 3, 0x34).Bytes);
                revision = database.RemoveNativeDocument(request.Username, name);
            }
            else
            {
                if (request.Operation == 0x178b || request.Operation == 0x178c)
                    database.EnsureNativeContactDocuments(request.Username);
                NativeDocumentSnapshot snapshot = database.GetNativeDocuments(request.Username);
                revision = snapshot.Revision;
                if (request.Operation == 0x178c || request.Operation == 0x178b)
                {
                    // VA 0074D090 accepts 4/35 as big-endian uint32 checksums.
                    byte[] checksums = new byte[checked(snapshot.Documents.Count * 4)];
                    for (int i = 0; i < snapshot.Documents.Count; i++)
                    {
                        uint value = snapshot.Documents[i].Checksum;
                        for (int j = 0; j < 4; j++) checksums[i * 4 + j] = (byte)(value >> (24 - 8 * j));
                    }
                    body.Add(new SkypeField { Type = 4, Id = 0x35, Bytes = checksums });
                }
                else if (request.Operation == 0x1788)
                {
                    uint checksum = SkypeBlobCodec.Required(request.Metadata, 0, 0x32).Number;
                    NativeDocument found = snapshot.Documents.Find(delegate(NativeDocument d) { return d.Checksum == checksum; });
                    if (found == null) throw new InvalidDataException("Native document is absent; refresh manifest");
                    // VA 0074E5B9: repeated 5/37, each containing 3/34 + 4/33.
                    body.Add(new SkypeField { Type = 5, Id = 0x37, Children = new List<SkypeField> {
                        new SkypeField { Type = 3, Id = 0x34, Bytes = Encoding.UTF8.GetBytes(found.Name) },
                        new SkypeField { Type = 4, Id = 0x33, Bytes = found.Body }
                    } });
                }
                else throw new InvalidDataException("Unsupported native document operation");
            }
            body.Insert(0, new SkypeField { Type = 0, Id = 0x36, Number = revision });
            return NativeCredentials.AccountResponse(SkypeBlobCodec.Encode(body), request.RequestId, 0x1450);
        }

        internal static void ValidateDocument(string name, byte[] body, uint checksum)
        {
            ValidateName(name);
            if (body == null || body.Length == 0 || body.Length > 12000)
                throw new InvalidDataException("Native document size limit");
            // VA 0074E611 seeds the CRC accumulator with FFFFFFFF; 006C1570
            // applies the standard reflected CRC polynomial without final XOR.
            if (NativeLoginRequest.Crc(body, body.Length) != checksum)
                throw new InvalidDataException("Native document checksum mismatch");
        }

        internal static void ValidateName(string name)
        {
            if (String.IsNullOrEmpty(name) || Encoding.UTF8.GetByteCount(name) > 255)
                throw new InvalidDataException("Invalid native document name");
            foreach (char c in name)
                if (Char.IsControl(c) || c == '|') throw new InvalidDataException("Invalid native document name");
        }

        internal static byte[] ContactDocument(Account contact)
        {
            // Live 4.2 upload u/echo123: 3/10 = Skype name, 0/79 = 2.
            // 0/7D is remote authorization; do not copy Echo's implicit grant.
            return SkypeBlobCodec.Encode(new List<SkypeField> {
                new SkypeField { Type = 3, Id = 0x10, Bytes = Encoding.UTF8.GetBytes(contact.Login) },
                new SkypeField { Type = 3, Id = 0x14, Bytes = Encoding.UTF8.GetBytes(contact.DisplayName) },
                new SkypeField { Type = 0, Id = 0x79, Number = 2 }
            });
        }
    }
}
