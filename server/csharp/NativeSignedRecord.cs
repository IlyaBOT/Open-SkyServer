using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SkyServer
{
    // The 4/B directory value is a length-prefixed authority credential,
    // followed by a client RSA recovery signature and optional message tail.
    // This verifies ownership of a record; it does not assert online presence.
    internal sealed class NativeSignedRecord
    {
        internal string Username;
        internal List<SkypeField> Fields;

        internal static NativeSignedRecord Verify(byte[] value, CommunityKeys keys, DateTime utcNow)
        {
            if (keys == null) throw new ArgumentNullException("keys");
            if (utcNow.Kind != DateTimeKind.Utc) throw new ArgumentException("UTC time required");
            if (value == null || value.Length < 392 || value.Length > 8192 ||
                value[0] != 0 || value[1] != 0 || value[2] != 1 || value[3] != 4)
                throw new InvalidDataException("Unsupported signed directory record envelope");
            byte[] credential = Slice(value, 4, 260);
            List<SkypeField> identity = keys.RecoverCredential(credential);
            string username = new UTF8Encoding(false, true).GetString(SkypeBlobCodec.Required(identity, 3, 0).Bytes);
            if (username.Length == 0 || username.Length > 128 || username.IndexOfAny(new[] { '\0', '\r', '\n', '\t' }) >= 0)
                throw new InvalidDataException("Invalid directory record identity");
            uint expiry = SkypeBlobCodec.Required(identity, 0, 4).Number;
            if (utcNow >= new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMinutes(expiry))
                throw new CryptographicException("Expired directory credential");
            byte[] modulus = SkypeBlobCodec.Required(identity, 4, 1).Bytes;
            if (modulus.Length != 128 || (modulus[0] & 128) == 0 || (modulus[127] & 1) == 0)
                throw new CryptographicException("Invalid directory client public key");
            byte[] block = CommunityKeys.PublicOperation(Slice(value, 264, 128),
                new RSAParameters { Modulus = modulus, Exponent = new byte[] { 1, 0, 1 } });
            if (block[127] != 0xbc) throw new CryptographicException("Invalid record recovery trailer");
            int start = 1;
            if (block[0] == 0x4b)
            {
                while (start < 107 && block[start] == 0xbb) start++;
                if (start >= 106 || block[start++] != 0xba)
                    throw new CryptographicException("Invalid record recovery padding");
            }
            else if (block[0] != 0x4a && block[0] != 0x6a)
                throw new CryptographicException("Unsupported record recovery header");
            if ((block[0] == 0x6a) != (value.Length > 392) || 107 - start <= 20)
                throw new CryptographicException("Invalid record recovery extent");
            byte[] message = new byte[107 - start + value.Length - 392];
            Buffer.BlockCopy(block, start, message, 0, 107 - start);
            Buffer.BlockCopy(value, 392, message, 107 - start, value.Length - 392);
            using (SHA1 sha = SHA1.Create())
            {
                RequireDigest(sha.ComputeHash(message), block, 107, "record digest");
                RequireDigest(sha.ComputeHash(credential), message, 0, "record credential binding");
            }
            byte[] payload = Slice(message, 20, message.Length - 20);
            int consumed;
            List<SkypeField> fields = SkypeBlobCodec.Decode(payload, out consumed);
            if (consumed != payload.Length) throw new InvalidDataException("Trailing directory record data");
            return new NativeSignedRecord { Username = username, Fields = fields };
        }

        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }

        private static void RequireDigest(byte[] expected, byte[] source, int offset, string name)
        {
            int difference = 0;
            for (int i = 0; i < expected.Length; i++) difference |= expected[i] ^ source[offset + i];
            if (difference != 0) throw new CryptographicException("Invalid " + name);
        }
    }
}
