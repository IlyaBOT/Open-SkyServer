using System;
using System.Numerics;
using System.Security.Cryptography;

namespace SkyServer
{
    internal sealed class SkypeDh384Session
    {
        public const int PublicKeyBytes = 48;

        private static readonly BigInteger Modulus = FromBigEndian(
            FromHex("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B13B202FFFFFFFFFFFFFFFF"),
            0,
            PublicKeyBytes);

        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        private static readonly object RngLock = new object();

        private readonly byte[] expectedClientHash;
        private readonly byte[] serverHash;
        private readonly byte[] serverHello;
        private readonly byte[] sharedSecret;

        public SkypeDh384Session(byte[] clientFirstPacket, int length)
        {
            if (clientFirstPacket == null)
            {
                throw new ArgumentNullException("clientFirstPacket");
            }

            if (length < PublicKeyBytes)
            {
                throw new ArgumentException("DH384 packet is shorter than the public key", "length");
            }

            BigInteger clientPublic = FromBigEndian(clientFirstPacket, 0, PublicKeyBytes);
            if (clientPublic <= BigInteger.One || clientPublic >= Modulus)
            {
                throw new ArgumentException("DH384 public key is outside the valid range", "clientFirstPacket");
            }

            BigInteger secret = GenerateSecret();
            BigInteger serverPublic = BigInteger.ModPow(new BigInteger(2), secret, Modulus);
            BigInteger shared = BigInteger.ModPow(clientPublic, secret, Modulus);

            byte[] publicBytes = ToBigEndian(serverPublic, PublicKeyBytes);
            sharedSecret = ToBigEndian(shared, PublicKeyBytes);
            expectedClientHash = HashWithPrefix((byte)'O', sharedSecret);
            serverHash = HashWithPrefix((byte)'I', sharedSecret);

            serverHello = new byte[51];
            Buffer.BlockCopy(publicBytes, 0, serverHello, 0, PublicKeyBytes);
            FillRandom(serverHello, PublicKeyBytes, serverHello.Length - PublicKeyBytes);
        }

        public byte[] ServerHello
        {
            get { return Clone(serverHello); }
        }

        public byte[] ServerHash
        {
            get { return Clone(serverHash); }
        }

        public byte[] ExpectedClientHash
        {
            get { return Clone(expectedClientHash); }
        }

        public byte[] SharedSecret
        {
            get { return Clone(sharedSecret); }
        }

        public bool VerifyClientHash(byte[] buffer, int length)
        {
            if (buffer == null || length < expectedClientHash.Length)
            {
                return false;
            }

            for (int i = 0; i < expectedClientHash.Length; i++)
            {
                if (buffer[i] != expectedClientHash[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static BigInteger GenerateSecret()
        {
            byte[] bytes = new byte[PublicKeyBytes];
            BigInteger secret;

            do
            {
                FillRandom(bytes, 0, bytes.Length);
                bytes[0] &= 0x7F;
                secret = FromBigEndian(bytes, 0, bytes.Length);
            }
            while (secret <= BigInteger.One || secret >= Modulus);

            return secret;
        }

        private static byte[] HashWithPrefix(byte prefix, byte[] data)
        {
            byte[] input = new byte[data.Length + 1];
            input[0] = prefix;
            Buffer.BlockCopy(data, 0, input, 1, data.Length);

            byte[] hash;
            using (MD5 md5 = MD5.Create())
            {
                hash = md5.ComputeHash(input);
            }

            byte[] result = new byte[8];
            Buffer.BlockCopy(hash, 0, result, 0, result.Length);
            return result;
        }

        private static BigInteger FromBigEndian(byte[] bytes, int offset, int count)
        {
            byte[] littleEndian = new byte[count + 1];
            for (int i = 0; i < count; i++)
            {
                littleEndian[i] = bytes[offset + count - 1 - i];
            }

            return new BigInteger(littleEndian);
        }

        private static byte[] ToBigEndian(BigInteger value, int count)
        {
            byte[] littleEndian = value.ToByteArray();
            byte[] result = new byte[count];
            int copyBytes = Math.Min(count, littleEndian.Length);

            for (int i = 0; i < copyBytes; i++)
            {
                result[count - 1 - i] = littleEndian[i];
            }

            return result;
        }

        private static void FillRandom(byte[] buffer, int offset, int count)
        {
            byte[] random = new byte[count];
            lock (RngLock)
            {
                Rng.GetBytes(random);
            }

            Buffer.BlockCopy(random, 0, buffer, offset, count);
        }

        private static byte[] FromHex(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hex string must contain an even number of characters", "hex");
            }

            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return result;
        }

        private static byte[] Clone(byte[] bytes)
        {
            return (byte[])bytes.Clone();
        }
    }
}
