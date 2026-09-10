using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SkyServer
{
    internal sealed class NativeLoginRequest : IDisposable
    {
        public string Username;
        public byte[] PasswordDigest;
        public byte[] ClientPublicKey;
        public byte[] AesKey;
        public uint Operation;
        public uint RequestId;

        public static NativeLoginRequest Parse(byte[] keyRecord, byte[] loginRecord, CommunityKeys keys)
        {
            byte[] keyPayload = Payload(keyRecord, 0x16);
            byte[] protectedLogin = Payload(loginRecord, 0x17);
            int consumed;
            List<SkypeField> exchange = SkypeBlobCodec.Decode(keyPayload, out consumed);
            if (consumed != keyPayload.Length) throw new InvalidDataException("Trailing key-exchange fields");
            byte[] encryptedMaterial = SkypeBlobCodec.Required(exchange, 4, 8).Bytes;
            if (encryptedMaterial.Length != 192) throw new InvalidDataException("Expected RSA-1536 key exchange");
            if (protectedLogin.Length < 3) throw new InvalidDataException("Short protected login record");
            int length = protectedLogin.Length - 2;
            uint crc = Crc(protectedLogin, length);
            if (protectedLogin[length] != (byte)crc || protectedLogin[length + 1] != (byte)(crc >> 8))
                throw new InvalidDataException("Native login CRC mismatch");
            NativeLoginRequest request = new NativeLoginRequest();
            byte[] material = null, clear = null;
            try
            {
                material = keys.DecryptLoginBlock(encryptedMaterial);
                if (material[0] != 1) throw new CryptographicException("RSA session material rejected; client may still trust the original authority");
                request.AesKey = CommunityKeys.DeriveLoginAesKey(material);
                byte[] ciphertext = new byte[length];
                Buffer.BlockCopy(protectedLogin, 0, ciphertext, 0, length);
                clear = CommunityKeys.LoginAesCtr(request.AesKey, ciphertext, 0);
                List<SkypeField> account = SkypeBlobCodec.Decode(clear, out consumed);
                uint operation = SkypeBlobCodec.Required(account, 0, 0).Number;
                request.Operation = operation;
                // 4.2 account_manager_t at VA 005A8191 submits 0x1399;
                // the later reconstructed client uses 0x13a3 with the same fields.
                if (operation != 0x1399 && operation != 0x13a3 && operation != 0x139c)
                    throw new InvalidDataException("Unsupported native operation 0x" + operation.ToString("X") + "; fields " + DescribeFields(account));
                // The live client increments 0/2 between account RPCs (1 for
                // login, 2 for email). Preserve it in the response envelope.
                request.RequestId = SkypeBlobCodec.Required(account, 0, 2).Number;
                if (request.RequestId == 0) throw new InvalidDataException("Zero native request identifier");
                request.Username = new UTF8Encoding(false, true).GetString(SkypeBlobCodec.Required(account, 3, 4).Bytes);
                if (request.Username.Length == 0 || request.Username.Length > 128 || request.Username.IndexOfAny(new[] { '\r', '\n', '\t', '\0' }) >= 0)
                    throw new InvalidDataException("Invalid native username");
                request.PasswordDigest = SkypeBlobCodec.Required(account, 4, 5).Bytes;
                if (request.PasswordDigest.Length != 16) throw new InvalidDataException("Expected native MD5 password verifier");
                byte[] metadata = new byte[clear.Length - consumed];
                Buffer.BlockCopy(clear, consumed, metadata, 0, metadata.Length);
                List<SkypeField> client = SkypeBlobCodec.Decode(metadata, out consumed);
                if (consumed != metadata.Length) throw new InvalidDataException("Trailing client metadata");
                if (operation == 0x139c) return request;
                request.ClientPublicKey = SkypeBlobCodec.Required(client, 4, 0x21).Bytes;
                if (request.ClientPublicKey.Length != 128 || (request.ClientPublicKey[0] & 0x80) == 0 || (request.ClientPublicKey[127] & 1) == 0)
                    throw new InvalidDataException("Expected a 1024-bit odd client RSA modulus");
                return request;
            }
            catch { request.Dispose(); throw; }
            finally
            {
                if (material != null) Array.Clear(material, 0, material.Length);
                if (clear != null) Array.Clear(clear, 0, clear.Length);
            }
        }

        internal static string DescribeFields(List<SkypeField> fields)
        {
            // Structural diagnostics only. Never log usernames, password digests,
            // session material, or other field values from an auth request.
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < Math.Min(fields.Count, 32); i++)
            {
                SkypeField field = fields[i];
                if (i != 0) result.Append(",");
                result.Append(field.Type).Append(":").Append(field.Id.ToString("X"));
                if (field.Bytes != null) result.Append("[").Append(field.Bytes.Length).Append("]");
                if (field.Children != null) result.Append("{").Append(field.Children.Count).Append("}");
            }
            if (fields.Count > 32) result.Append(",...");
            return result.ToString();
        }

        private static byte[] Payload(byte[] record, byte type)
        {
            if (record == null || record.Length < 5 || record[0] != type || record[1] != 3 || record[2] != 1 ||
                ((record[3] << 8) | record[4]) != record.Length - 5 || record.Length > 16389)
                throw new InvalidDataException("Invalid native auth record");
            byte[] result = new byte[record.Length - 5];
            Buffer.BlockCopy(record, 5, result, 0, result.Length);
            return result;
        }

        internal static uint Crc(byte[] bytes, int count)
        {
            uint crc = UInt32.MaxValue;
            for (int i = 0; i < count; i++)
            {
                crc ^= bytes[i];
                for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ ((crc & 1) == 1 ? 0xedb88320U : 0U);
            }
            return crc;
        }

        public void Dispose()
        {
            if (PasswordDigest != null) Array.Clear(PasswordDigest, 0, PasswordDigest.Length);
            if (AesKey != null) Array.Clear(AesKey, 0, AesKey.Length);
        }
    }
}
