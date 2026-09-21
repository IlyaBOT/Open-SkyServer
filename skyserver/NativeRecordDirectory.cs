using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace SkyServer
{
    // Transient signed location records, not an authoritative presence table.
    internal sealed class NativeRecordDirectory
    {
        private sealed class Entry { internal byte[] Value; internal DateTime Expires; internal uint Id; }
        private readonly CommunityKeys keys;
        private readonly Dictionary<string, Entry> records = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        private readonly object sync = new object();

        internal NativeRecordDirectory(CommunityKeys keys) { this.keys = keys; }

        internal SkypeNodeCommand Handle(SkypeNodeCommand request, DateTime now)
        {
            if (request.Code != 0xc && request.Code != 0xe) return null;
            if (now.Kind != DateTimeKind.Utc) throw new ArgumentException("UTC time required");
            if (request.Flags != 2 || !request.RequestId.HasValue)
                throw new InvalidDataException("Invalid directory request header");
            List<SkypeField> result = new List<SkypeField>();
            if (request.Code == 0xc)
            {
                if (keys == null) return null;
                if (request.Fields.Count != 1) throw new InvalidDataException("Unsupported directory publication fields");
                byte[] value = SkypeBlobCodec.Required(request.Fields, 4, 0xb).Bytes;
                NativeSignedRecord record = NativeSignedRecord.Verify(value, keys, now);
                lock (sync)
                {
                    Expire(now);
                    if (records.Count >= 1024 && !records.ContainsKey(record.Username))
                        throw new InvalidDataException("Directory capacity reached");
                    uint id;
                    using (SHA256 sha = SHA256.Create()) id = BitConverter.ToUInt32(sha.ComputeHash(value), 0);
                    records[record.Username] = new Entry { Value = (byte[])value.Clone(), Expires = now.AddMinutes(2), Id = id };
                }
                Console.WriteLine("directory stored verified location user={0} bytes={1}", record.Username, value.Length);
            }
            else
            {
                if (request.Fields.Count != 2 && request.Fields.Count != 3) return null;
                byte[] excluded = request.Fields.Count == 3 ? SkypeBlobCodec.Required(request.Fields, 6, 2).Bytes : new byte[0];
                if (excluded.Length > 400 || excluded.Length % 4 != 0)
                    throw new InvalidDataException("Invalid excluded location identifiers");
                List<SkypeField> query = SkypeBlobCodec.Required(request.Fields, 5, 0).Children;
                byte[] properties = SkypeBlobCodec.Required(request.Fields, 6, 1).Bytes;
                if (query.Count != 3 || properties.Length != 8 || BitConverter.ToUInt32(properties, 0) != 16 ||
                    BitConverter.ToUInt32(properties, 4) != 11) return null;
                string username = new UTF8Encoding(false, true).GetString(SkypeBlobCodec.Required(query, 3, 0).Bytes);
                uint offset = SkypeBlobCodec.Required(query, 0, 1).Number;
                uint limit = SkypeBlobCodec.Required(query, 0, 2).Number;
                if (username.Length == 0 || username.Length > 128 || limit == 0 || limit > 100)
                    throw new InvalidDataException("Invalid location query");
                lock (sync)
                {
                    Expire(now);
                    Entry entry;
                    if (offset == 0 && records.TryGetValue(username, out entry))
                    {
                        bool omit = false;
                        for (int i = 0; i < excluded.Length; i += 4) omit |= BitConverter.ToUInt32(excluded, i) == entry.Id;
                        if (!omit) result.Add(new SkypeField { Type = 5, Id = 0, Children = new List<SkypeField> {
                            new SkypeField { Type = 0, Id = 0x10, Number = entry.Id },
                            new SkypeField { Type = 4, Id = 0xb, Bytes = (byte[])entry.Value.Clone() }
                        } });
                    }
                }
                // Searcher 0062DA40 iterates 5/0 results; 0/1=0 marks the end.
                result.Add(new SkypeField { Type = 0, Id = 1, Number = 0 });
                Console.WriteLine("directory location query results={0}", result.Count - 1);
            }
            return new SkypeNodeCommand { Code = request.Code + 1, Flags = 3, RequestId = request.RequestId, Fields = result };
        }

        private void Expire(DateTime now)
        {
            List<string> expired = new List<string>();
            foreach (KeyValuePair<string, Entry> item in records)
                if (item.Value.Expires <= now) expired.Add(item.Key);
            foreach (string username in expired) records.Remove(username);
        }
    }
}
