using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SkyServer
{
    internal sealed class NativeDirectoryTerm
    {
        public uint Property;
        public uint Comparison;
        public string Text;
        public uint? Number;
    }

    internal static class NativeDirectorySearch
    {
        internal static byte[] Respond(NativeLoginRequest request, SkyDatabase database)
        {
            if (request.Operation != 0x4278) throw new InvalidDataException("Not a native directory request");
            // 4.2 VA 00643530: repeated 5/20 with property 0/21,
            // comparison 0/22, value */23; 0/24 controls DHT fallback.
            uint noFallback = SkypeBlobCodec.Required(request.Metadata, 0, 0x24).Number;
            if (noFallback > 1) throw new InvalidDataException("Invalid directory fallback flag");
            List<NativeDirectoryTerm> terms = new List<NativeDirectoryTerm>();
            foreach (SkypeField field in request.Metadata)
            {
                if (field.Id != 0x20) continue;
                if (field.Type != 5 || field.Children == null || field.Children.Count != 3)
                    throw new InvalidDataException("Invalid native directory term");
                uint property = SkypeBlobCodec.Required(field.Children, 0, 0x21).Number;
                uint comparison = SkypeBlobCodec.Required(field.Children, 0, 0x22).Number;
                Console.WriteLine("native directory term: property={0}, comparison={1}, fields={2}",
                    property, comparison, NativeLoginRequest.DescribeFields(field.Children));
                NativeDirectoryTerm term = new NativeDirectoryTerm { Property = property, Comparison = comparison };
                if (property == 17) term.Number = SkypeBlobCodec.Required(field.Children, 0, 0x23).Number;
                else term.Text = new UTF8Encoding(false, true).GetString(SkypeBlobCodec.Required(field.Children, 3, 0x23).Bytes);
                terms.Add(term);
            }
            List<Account> matches = database.SearchNativeDirectory(terms);
            List<SkypeField> results = new List<SkypeField>();
            foreach (Account match in matches)
            {
                // VA 00643A40: 5/64, 3/66 -> skypename, 3/65 -> fullname.
                // Optional location and rank fields are omitted, not invented.
                results.Add(new SkypeField { Type = 5, Id = 0x64, Children = new List<SkypeField> {
                    new SkypeField { Type = 3, Id = 0x66, Bytes = Encoding.UTF8.GetBytes(match.Login) },
                    new SkypeField { Type = 3, Id = 0x65, Bytes = Encoding.UTF8.GetBytes(match.DisplayName) }
                } });
            }
            Console.WriteLine("native directory: terms={0}, results={1}", terms.Count, matches.Count);
            // VA 00644140: 81B0 completes a search; 81B6 is a partial reply.
            return NativeCredentials.AccountResponse(SkypeBlobCodec.Encode(results), request.RequestId, 0x81b0);
        }

        internal static void ValidateTerm(NativeDirectoryTerm term)
        {
            // VA 00646920 inserts property 3/value 0 between alternatives;
            // VA 00643530 maps that property to wire ID 17.
            if (term != null && term.Property == 17)
            {
                if (term.Comparison != 0 || term.Number != 0 || term.Text != null)
                    throw new InvalidDataException("Unsupported directory logical operator");
                return;
            }
            if (term == null || String.IsNullOrWhiteSpace(term.Text) || Encoding.UTF8.GetByteCount(term.Text) > 254)
                throw new InvalidDataException("Invalid directory query length");
            if (term.Number.HasValue) throw new InvalidDataException("Expected a directory string value");
            foreach (char c in term.Text)
                if (Char.IsControl(c)) throw new InvalidDataException("Control character in directory query");
            bool supported = term.Property == 0 && (term.Comparison == 0 || term.Comparison == 5) ||
                term.Property == 1 && (term.Comparison == 0 || term.Comparison == 8) ||
                term.Property == 2 && (term.Comparison == 0 || term.Comparison == 5 || term.Comparison == 8 || term.Comparison == 9);
            if (!supported)
                throw new InvalidDataException("Unsupported directory filter: property=" + term.Property + ", comparison=" + term.Comparison);
        }
    }
}
