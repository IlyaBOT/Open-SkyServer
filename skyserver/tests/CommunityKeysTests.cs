using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using SkyServer;

internal static class CommunityKeysTests
{
    public static void Run(string root)
    {
        string directory = Path.Combine(root, "test-only-authority");
        Directory.CreateDirectory(directory);
        DirectorySecurity acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.SetAccessControl(directory, acl);
        try
        {
            Generate(directory, "login", 1536);
            Generate(directory, "credentials", 2048);
            CommunityKeys keys = CommunityKeys.Load(directory);
            byte[] material = new byte[192];
            for (int i = 0; i < material.Length; i++) material[i] = (byte)i;
            material[0] = 1;
            using (RSACryptoServiceProvider pub = new RSACryptoServiceProvider())
            {
                pub.PersistKeyInCsp = false;
                pub.FromXmlString(File.ReadAllText(Path.Combine(directory, "login.public.xml")));
                RSAParameters p = pub.ExportParameters(false);
                byte[] ciphertext = CommunityKeys.PublicOperation(material, p);
                Equal(keys.DecryptLoginBlock(ciphertext), material, "raw RSA decrypt");
                Reject(delegate { keys.DecryptLoginBlock(new byte[191]); }, "short RSA block");
                Reject(delegate { keys.DecryptLoginBlock(p.Modulus); }, "RSA representative >= modulus");
                byte[] changed = (byte[])ciphertext.Clone();
                changed[191] ^= 1;
                if (Convert.ToBase64String(keys.DecryptLoginBlock(changed)) == Convert.ToBase64String(material))
                    throw new Exception("Changed ciphertext unexpectedly preserved material");
            }
            using (RSACryptoServiceProvider pub = new RSACryptoServiceProvider())
            {
                pub.PersistKeyInCsp = false;
                pub.FromXmlString(File.ReadAllText(Path.Combine(directory, "credentials.public.xml")));
                byte[] encoded = new byte[256];
                encoded[0] = 0x4b; encoded[255] = 0xbc;
                Equal(CommunityKeys.PublicOperation(keys.SignCredentialBlock(encoded), pub.ExportParameters(false)), encoded, "credential raw signature recovery");
            }
            // Vectors emitted by LoginCryptoReference.c, which uses the original C implementation.
            byte[] key = CommunityKeys.DeriveLoginAesKey(material);
            Equal(key, Hex("61D4246427679FAD1483710C64687FBE4C464A2B3E32C2A8EFFDD5E743858B95"), "native KDF vector");
            byte[] plain = new byte[49];
            for (int i = 0; i < plain.Length; i++) plain[i] = (byte)i;
            string[] expected = {
                "EC4C5CC1625A6DA47B63E26654655EA6FA09772F5224533F8AB9542F3E6F4B5F4B152CDB4F51A26A601CD4DD379667E55F",
                "DFC4B8C85D3FFDE7208D4AA67105168896962D7CC781B9B0F555070C96ACE347685E7390397D9F08F337B0203ABB07AAD0"
            };
            for (uint iv = 0; iv <= 1; iv++)
            {
                byte[] cipher = CommunityKeys.LoginAesCtr(key, plain, iv);
                Equal(cipher, Hex(expected[iv]), "native AES-CTR vector " + iv);
                Equal(CommunityKeys.LoginAesCtr(key, cipher, iv), plain, "AES roundtrip " + iv);
                foreach (int length in new[] { 0, 1, 15, 16, 17, 32, 48 })
                {
                    byte[] part = new byte[length];
                    byte[] reference = new byte[length];
                    Buffer.BlockCopy(plain, 0, part, 0, length);
                    Buffer.BlockCopy(cipher, 0, reference, 0, length);
                    Equal(CommunityKeys.LoginAesCtr(key, part, iv), reference, "AES partial block " + length);
                }
            }
            Reject(delegate { CommunityKeys.DeriveLoginAesKey(new byte[191]); }, "KDF length");
            Reject(delegate { CommunityKeys.LoginAesCtr(new byte[31], plain, 0); }, "AES key length");
            File.Copy(Path.Combine(directory, "credentials.public.xml"), Path.Combine(directory, "login.public.xml"), true);
            Reject(delegate { CommunityKeys.Load(directory); }, "mismatched key pair");
            Generate(directory, "login", 1024);
            Reject(delegate { CommunityKeys.Load(directory); }, "wrong key size");
            File.WriteAllText(Path.Combine(directory, "login.private.xml"), "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///not-read'>]><RSAKeyValue>&e;</RSAKeyValue>");
            Reject(delegate { CommunityKeys.Load(directory); }, "DTD prohibited");
            Console.WriteLine("PASS authority tests: RSA pairs, raw operations, native C KDF/AES vectors, boundaries, invalid keys and DTD rejection.");
        }
        finally
        {
            foreach (string name in new[] { "login.private.xml", "login.public.xml", "credentials.private.xml", "credentials.public.xml" })
                File.Delete(Path.Combine(directory, name));
            Directory.Delete(directory, false);
        }
    }

    private static void Generate(string directory, string name, int bits)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(bits))
        {
            rsa.PersistKeyInCsp = false;
            File.WriteAllText(Path.Combine(directory, name + ".private.xml"), rsa.ToXmlString(true));
            File.WriteAllText(Path.Combine(directory, name + ".public.xml"), rsa.ToXmlString(false));
        }
    }

    private static byte[] Hex(string hex)
    {
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++) result[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
        return result;
    }

    private static void Equal(byte[] a, byte[] b, string label)
    {
        if (Convert.ToBase64String(a) != Convert.ToBase64String(b)) throw new Exception("Failed: " + label);
    }

    private static void Reject(Action action, string label)
    {
        try { action(); }
        catch (CryptographicException) { return; }
        catch (System.Xml.XmlException) { return; }
        throw new Exception("Expected rejection: " + label);
    }
}
