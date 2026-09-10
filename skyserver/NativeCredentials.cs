using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SkyServer
{
    internal static class NativeCredentials
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        internal static byte[] Issue(CommunityKeys keys, string username, byte[] clientModulus, DateTime utcNow)
        {
            if (keys == null) throw new ArgumentNullException("keys");
            if (utcNow.Kind != DateTimeKind.Utc || utcNow < Epoch)
                throw new ArgumentException("UTC issuance time required");
            if (String.IsNullOrEmpty(username) || username.IndexOfAny(new[] { '\0', '\r', '\n', '\t' }) >= 0)
                throw new InvalidDataException("Invalid credential username");
            if (clientModulus == null || clientModulus.Length != 128 || (clientModulus[0] & 0x80) == 0 ||
                (clientModulus[127] & 1) == 0)
                throw new InvalidDataException("Expected a 1024-bit client modulus");

            // 0/4 is expiry in Unix minutes. Nested 5/2 -> 0/9 is opaque:
            // the old cred_util.c interprets it as a date shifted by 365 days.
            // This compatibility hypothesis still needs a patched-client test.
            uint expiry = Minutes(utcNow.AddDays(30));
            uint opaqueDate = Minutes(utcNow.AddDays(365));
            byte[] payload = SkypeBlobCodec.Encode(new List<SkypeField> {
                new SkypeField { Type = 3, Id = 0, Bytes = new UTF8Encoding(false, true).GetBytes(username) },
                Number(3, 0),
                new SkypeField { Type = 4, Id = 1, Bytes = clientModulus },
                Number(4, expiry),
                new SkypeField { Type = 5, Id = 2, Children = new List<SkypeField> { Number(9, opaqueDate) } }
            });
            byte[] signature = keys.SignCredentialBlock(EncodeRecoveredBlock(payload));
            byte[] credential = new byte[260];
            credential[3] = 1;
            Buffer.BlockCopy(signature, 0, credential, 4, signature.Length);
            return credential;
        }

        // Full-message recovery, SHA-1, implicit trailer. Proven against three
        // historical authority signatures; partial-message recovery is not used.
        internal static byte[] EncodeRecoveredBlock(byte[] payload)
        {
            if (payload == null || payload.Length == 0 || payload.Length > 234)
                throw new InvalidDataException("Credential does not fit the RSA recovery block");
            byte[] block = new byte[256];
            int start = 235 - payload.Length;
            if (start == 1) block[0] = 0x4a;
            else
            {
                block[0] = 0x4b;
                for (int i = 1; i < start - 1; i++) block[i] = 0xbb;
                block[start - 1] = 0xba;
            }
            Buffer.BlockCopy(payload, 0, block, start, payload.Length);
            using (SHA1 sha = SHA1.Create()) Buffer.BlockCopy(sha.ComputeHash(payload), 0, block, 235, 20);
            block[255] = 0xbc;
            return block;
        }

        internal static byte[] DecodeRecoveredBlock(byte[] block)
        {
            if (block == null || block.Length != 256 || block[255] != 0xbc)
                throw new CryptographicException("Invalid credential recovery trailer");
            int start = 1;
            if (block[0] == 0x4b)
            {
                while (start < 235 && block[start] == 0xbb) start++;
                if (start >= 234 || block[start] != 0xba)
                    throw new CryptographicException("Invalid credential recovery padding");
                start++;
            }
            else if (block[0] != 0x4a) throw new CryptographicException("Unsupported credential recovery header");
            byte[] payload = new byte[235 - start];
            Buffer.BlockCopy(block, start, payload, 0, payload.Length);
            byte[] digest;
            using (SHA1 sha = SHA1.Create()) digest = sha.ComputeHash(payload);
            int different = 0;
            for (int i = 0; i < 20; i++) different |= digest[i] ^ block[235 + i];
            if (different != 0) throw new CryptographicException("Credential digest mismatch");
            return payload;
        }

        internal static List<SkypeField> Recover(byte[] credential, RSAParameters authority)
        {
            if (credential == null || credential.Length != 260 || credential[0] != 0 ||
                credential[1] != 0 || credential[2] != 0 || credential[3] != 1 ||
                authority.Modulus == null || authority.Modulus.Length != 256 ||
                authority.Exponent == null || authority.Exponent.Length != 3 ||
                authority.Exponent[0] != 1 || authority.Exponent[1] != 0 || authority.Exponent[2] != 1)
                throw new CryptographicException("Unsupported credential authority");
            byte[] signature = new byte[256];
            Buffer.BlockCopy(credential, 4, signature, 0, 256);
            byte[] payload = DecodeRecoveredBlock(CommunityKeys.PublicOperation(signature, authority));
            int consumed;
            List<SkypeField> fields = SkypeBlobCodec.Decode(payload, out consumed);
            if (consumed != payload.Length) throw new InvalidDataException("Trailing credential fields");
            return fields;
        }

        internal static byte[] SuccessPayload(byte[] credential, uint requestId = 1)
        {
            if (credential == null || credential.Length != 260)
                throw new InvalidDataException("Expected a 260-byte credential");
            // skyauth3/Debug/log.txt, "Server AES Reply": two consecutive lists.
            byte[] body = SkypeBlobCodec.Encode(new List<SkypeField> {
                Number(0x3a, 2), Number(0x3c, 0),
                new SkypeField { Type = 4, Id = 0x24, Bytes = credential },
                new SkypeField { Type = 5, Id = 0x32, Children = new List<SkypeField>() }
            });
            return AccountResponse(body, requestId);
        }

        internal static byte[] EmailPayload(string email, uint requestId = 1)
        {
            if (email == null || email.Length > 254 || email.IndexOfAny(new[] { '\0', '\r', '\n', '\t' }) >= 0)
                throw new InvalidDataException("Invalid account email");
            // 4.2 sender VA 005A2F80 / reply VA 005A33B0: 3/20 is merged
            // into property 0x40, named 'emails' by the table at VA 00D105CC.
            return AccountResponse(SkypeBlobCodec.Encode(new List<SkypeField> {
                new SkypeField { Type = 3, Id = 0x20, Bytes = new UTF8Encoding(false, true).GetBytes(email) }
            }), requestId);
        }

        private static byte[] AccountResponse(byte[] body, uint requestId)
        {
            if (requestId == 0) throw new InvalidDataException("Zero native response identifier");
            byte[] header = SkypeBlobCodec.Encode(new List<SkypeField> { Number(1, 0x1068), Number(2, requestId) });
            byte[] result = new byte[header.Length + body.Length];
            Buffer.BlockCopy(header, 0, result, 0, header.Length);
            Buffer.BlockCopy(body, 0, result, header.Length, body.Length);
            return result;
        }

        internal static byte[] ProtectResponse(byte[] payload, byte[] aesKey)
        {
            if (payload == null || payload.Length == 0 || payload.Length > 16382)
                throw new InvalidDataException("Invalid native response size");
            byte[] cipher = CommunityKeys.LoginAesCtr(aesKey, payload, 1);
            uint crc = NativeLoginRequest.Crc(cipher, cipher.Length);
            byte[] record = new byte[cipher.Length + 7];
            record[0] = 0x17; record[1] = 3; record[2] = 1;
            record[3] = (byte)((cipher.Length + 2) >> 8); record[4] = (byte)(cipher.Length + 2);
            Buffer.BlockCopy(cipher, 0, record, 5, cipher.Length);
            record[record.Length - 2] = (byte)crc;
            record[record.Length - 1] = (byte)(crc >> 8);
            return record;
        }

        private static uint Minutes(DateTime time) { return checked((uint)((time - Epoch).Ticks / TimeSpan.TicksPerMinute)); }
        private static SkypeField Number(uint id, uint value) { return new SkypeField { Type = 0, Id = id, Number = value }; }
    }
}
