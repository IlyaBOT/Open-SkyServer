using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Xml;

namespace SkyServer
{
    // Wire-compatible legacy sizes, not a cryptographic design for new applications.
    internal sealed class CommunityKeys
    {
        private readonly RSAParameters login;
        private readonly RSAParameters credentials;

        private CommunityKeys(RSAParameters login, RSAParameters credentials)
        {
            this.login = login;
            this.credentials = credentials;
        }

        public string LoginFingerprint { get { return Fingerprint(login.Modulus); } }
        public string CredentialsFingerprint { get { return Fingerprint(credentials.Modulus); } }

        public static CommunityKeys Load(string directory)
        {
            CommunityKeys keys = new CommunityKeys(
                LoadPair(directory, "login", 1536), LoadPair(directory, "credentials", 2048));
            keys.SelfTest();
            return keys;
        }

        private static RSAParameters LoadPair(string directory, string name, int bits)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (RSACryptoServiceProvider pub = new RSACryptoServiceProvider())
            {
                rsa.PersistKeyInCsp = false;
                pub.PersistKeyInCsp = false;
                rsa.FromXmlString(ReadKeyXml(Path.Combine(directory, name + ".private.xml")));
                pub.FromXmlString(ReadKeyXml(Path.Combine(directory, name + ".public.xml")));
                RSAParameters p = rsa.ExportParameters(true);
                RSAParameters q = pub.ExportParameters(false);
                if (rsa.KeySize != bits || p.Modulus.Length != bits / 8 || p.D == null ||
                    !Equal(p.Exponent, new byte[] { 1, 0, 1 }) ||
                    !Equal(p.Modulus, q.Modulus) || !Equal(p.Exponent, q.Exponent))
                    throw new CryptographicException("Invalid or mismatched " + name + " key pair");
                return p;
            }
        }

        private static string ReadKeyXml(string path)
        {
            FileInfo info = new FileInfo(path);
            if (info.Length > 16384) throw new InvalidDataException("RSA key file is too large");
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            XmlDocument document = new XmlDocument();
            document.XmlResolver = null;
            using (XmlReader reader = XmlReader.Create(path, settings)) document.Load(reader);
            if (document.DocumentElement == null || document.DocumentElement.Name != "RSAKeyValue")
                throw new InvalidDataException("Expected RSAKeyValue");
            return document.OuterXml;
        }

        public byte[] DecryptLoginBlock(byte[] ciphertext)
        {
            return PrivateOperation(ciphertext, login);
        }

        // Input must already contain the native credential encoding and padding.
        // This is deliberately not a generic network-accessible signing endpoint.
        internal byte[] SignCredentialBlock(byte[] encodedBlock)
        {
            return PrivateOperation(encodedBlock, credentials);
        }

        public void SelfTest()
        {
            foreach (RSAParameters key in new[] { login, credentials })
            {
                byte[] challenge = new byte[key.Modulus.Length];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(challenge);
                challenge[0] = 1;
                byte[] encrypted = PublicOperation(challenge, key);
                if (!Equal(PrivateOperation(encrypted, key), challenge))
                    throw new CryptographicException("RSA pair self-test failed");
            }
        }

        private static byte[] PrivateOperation(byte[] block, RSAParameters key)
        {
            if (block == null || block.Length != key.Modulus.Length)
                throw new CryptographicException("Incorrect raw RSA block length");
            BigInteger n = FromBigEndian(key.Modulus);
            BigInteger c = FromBigEndian(block);
            if (c >= n) throw new CryptographicException("Raw RSA block outside modulus");
            BigInteger e = FromBigEndian(key.Exponent);
            BigInteger r;
            byte[] random = new byte[key.Modulus.Length];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                do { rng.GetBytes(random); r = FromBigEndian(random); }
                while (r <= 1 || r >= n || BigInteger.GreatestCommonDivisor(r, n) != 1);
            }
            // Blind private exponentiation and verify before exposing its result.
            BigInteger blinded = (c * BigInteger.ModPow(r, e, n)) % n;
            BigInteger m = (BigInteger.ModPow(blinded, FromBigEndian(key.D), n) * Inverse(r, n)) % n;
            if (BigInteger.ModPow(m, e, n) != c)
                throw new CryptographicException("RSA private operation verification failed");
            return ToBigEndian(m, block.Length);
        }

        internal static byte[] PublicOperation(byte[] block, RSAParameters key)
        {
            BigInteger n = FromBigEndian(key.Modulus);
            BigInteger m = FromBigEndian(block);
            if (block.Length != key.Modulus.Length || m >= n)
                throw new CryptographicException("Invalid raw RSA input");
            return ToBigEndian(BigInteger.ModPow(m, FromBigEndian(key.Exponent), n), block.Length);
        }

        private static BigInteger Inverse(BigInteger a, BigInteger n)
        {
            BigInteger t = 0, nextT = 1, r = n, nextR = a;
            while (nextR != 0)
            {
                BigInteger q = r / nextR;
                BigInteger temp = t - q * nextT; t = nextT; nextT = temp;
                temp = r - q * nextR; r = nextR; nextR = temp;
            }
            if (r != 1) throw new CryptographicException("RSA blinding inverse failed");
            return t < 0 ? t + n : t;
        }

        private static BigInteger FromBigEndian(byte[] bytes)
        {
            byte[] le = new byte[bytes.Length + 1];
            for (int i = 0; i < bytes.Length; i++) le[i] = bytes[bytes.Length - 1 - i];
            return new BigInteger(le);
        }

        private static byte[] ToBigEndian(BigInteger value, int length)
        {
            byte[] le = value.ToByteArray();
            byte[] result = new byte[length];
            for (int i = 0; i < length && i < le.Length; i++) result[length - 1 - i] = le[i];
            return result;
        }

        internal static byte[] DeriveLoginAesKey(byte[] material)
        {
            if (material == null || material.Length != 192)
                throw new CryptographicException("Expected 192 bytes of RSA session material");
            byte[] input = new byte[196];
            Buffer.BlockCopy(material, 0, input, 4, material.Length);
            byte[] key = new byte[32];
            using (SHA1 sha = SHA1.Create())
            {
                Buffer.BlockCopy(sha.ComputeHash(input), 0, key, 0, 20);
                input[3] = 1;
                Buffer.BlockCopy(sha.ComputeHash(input), 0, key, 20, 12);
            }
            Array.Clear(input, 0, input.Length);
            return key;
        }

        internal static byte[] LoginAesCtr(byte[] key, byte[] data, uint iv)
        {
            if (key == null || key.Length != 32) throw new CryptographicException("AES-256 key required");
            byte[] result = new byte[data.Length];
            byte[] counter = new byte[16];
            Write32(counter, 0, iv);
            Write32(counter, 4, iv);
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (ICryptoTransform encrypt = aes.CreateEncryptor())
                {
                    byte[] pad = new byte[16];
                    for (int offset = 0; offset < data.Length; offset += 16)
                    {
                        Write32(counter, 12, (uint)(offset / 16));
                        encrypt.TransformBlock(counter, 0, 16, pad, 0);
                        for (int i = 0; i < 16 && offset + i < data.Length; i++)
                            result[offset + i] = (byte)(data[offset + i] ^ pad[i]);
                    }
                }
            }
            return result;
        }

        private static void Write32(byte[] data, int offset, uint value)
        {
            for (int i = 3; i >= 0; i--) { data[offset + i] = (byte)value; value >>= 8; }
        }

        private static bool Equal(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int difference = 0;
            for (int i = 0; i < a.Length; i++) difference |= a[i] ^ b[i];
            return difference == 0;
        }

        private static string Fingerprint(byte[] modulus)
        {
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(modulus)).Replace("-", "");
        }
    }
}
