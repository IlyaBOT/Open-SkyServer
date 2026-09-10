using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SkyServer
{
    internal static class SkypeNativeRc4
    {
        private const int MaxPacket = 256;
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        private static readonly object RngLock = new object();

        public static bool TryMakeServerHandshake(byte[] sharedSecret, out byte[] packet, out string error)
        {
            packet = null;
            error = null;

            try
            {
                byte[] output = new byte[MaxPacket];
                uint iv = NextUInt32();
                ushort sequence = (ushort)(NextUInt32() & 0xFFFF);
                int garbageLen = 20 + (int)(NextUInt32() % 16);
                int length = skype_make_server_handshake(sharedSecret, sharedSecret.Length, iv, sequence, garbageLen, output, output.Length);
                if (length <= 0)
                {
                    error = "native helper returned " + length;
                    return false;
                }

                packet = new byte[length];
                Buffer.BlockCopy(output, 0, packet, 0, packet.Length);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.GetType().Name + ": " + ex.Message;
                return false;
            }
        }

        public static bool TryDecryptHandshake(byte[] sharedSecret, byte[] encrypted, int encryptedLength, out byte[] packet, out string error)
        {
            packet = null;
            error = null;

            try
            {
                byte[] output = new byte[Math.Max(MaxPacket, encryptedLength)];
                int length = skype_probe_decrypt_handshake(sharedSecret, sharedSecret.Length, encrypted, encryptedLength, output, output.Length);
                if (length <= 0)
                {
                    error = "native helper returned " + length;
                    return false;
                }

                packet = new byte[length];
                Buffer.BlockCopy(output, 0, packet, 0, packet.Length);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.GetType().Name + ": " + ex.Message;
                return false;
            }
        }

        public static bool TryUdpCrypt(uint iv, byte[] input, int inputLength, out byte[] packet, out string error)
        {
            packet = null;
            error = null;

            try
            {
                byte[] output = new byte[Math.Max(MaxPacket, inputLength)];
                int length = skype_udp_crypt(iv, input, inputLength, output, output.Length);
                if (length <= 0)
                {
                    error = "native helper returned " + length;
                    return false;
                }

                packet = new byte[length];
                Buffer.BlockCopy(output, 0, packet, 0, packet.Length);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.GetType().Name + ": " + ex.Message;
                return false;
            }
        }

        private static uint NextUInt32()
        {
            byte[] bytes = new byte[4];
            lock (RngLock)
            {
                Rng.GetBytes(bytes);
            }

            return BitConverter.ToUInt32(bytes, 0);
        }

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int skype_make_server_handshake(
            byte[] sharedSecret,
            int sharedSecretLength,
            uint iv,
            ushort sequence,
            int garbageLength,
            byte[] output,
            int outputCapacity);

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int skype_probe_decrypt_handshake(
            byte[] sharedSecret,
            int sharedSecretLength,
            byte[] packet,
            int packetLength,
            byte[] output,
            int outputCapacity);

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int skype_udp_crypt(
            uint iv,
            byte[] input,
            int inputLength,
            byte[] output,
            int outputCapacity);

        internal sealed class Session : IDisposable
        {
            private IntPtr handle;

            public Session()
            {
                handle = skype_session_create();
                if (handle == IntPtr.Zero)
                {
                    throw new InvalidOperationException("skype_session_create returned null");
                }
            }

            ~Session()
            {
                Dispose(false);
            }

            public bool TryMakeServerHandshake(byte[] sharedSecret, out byte[] packet, out string error)
            {
                packet = null;
                error = null;

                try
                {
                    byte[] output = new byte[MaxPacket];
                    uint iv = NextUInt32();
                    ushort sequence = (ushort)(NextUInt32() & 0xFFFF);
                    int garbageLen = 20 + (int)(NextUInt32() % 16);
                    int length = skype_session_make_server_handshake(handle, sharedSecret, sharedSecret.Length, iv, sequence, garbageLen, output, output.Length);
                    if (length <= 0)
                    {
                        error = "native helper returned " + length;
                        return false;
                    }

                    packet = new byte[length];
                    Buffer.BlockCopy(output, 0, packet, 0, packet.Length);
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex.GetType().Name + ": " + ex.Message;
                    return false;
                }
            }

            public bool TryDecryptClientHandshake(byte[] sharedSecret, byte[] encrypted, int encryptedLength, out byte[] packet, out string error)
            {
                packet = null;
                error = null;

                try
                {
                    byte[] output = new byte[Math.Max(MaxPacket, encryptedLength)];
                    int length = skype_session_decrypt_client_handshake(handle, sharedSecret, sharedSecret.Length, encrypted, encryptedLength, output, output.Length);
                    if (length <= 0)
                    {
                        error = "native helper returned " + length;
                        return false;
                    }

                    packet = new byte[length];
                    Buffer.BlockCopy(output, 0, packet, 0, packet.Length);
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex.GetType().Name + ": " + ex.Message;
                    return false;
                }
            }

            public bool TryDecryptFromClient(byte[] encrypted, int encryptedLength, out byte[] packet, out string error)
            {
                return Crypt(skype_session_decrypt_from_client, encrypted, encryptedLength, out packet, out error);
            }

            public bool TryEncryptToClient(byte[] clear, int clearLength, out byte[] packet, out string error)
            {
                return Crypt(skype_session_encrypt_to_client, clear, clearLength, out packet, out error);
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            private bool Crypt(SessionCrypt crypt, byte[] input, int inputLength, out byte[] packet, out string error)
            {
                packet = null;
                error = null;

                try
                {
                    byte[] output = new byte[Math.Max(MaxPacket, inputLength)];
                    int length = crypt(handle, input, inputLength, output, output.Length);
                    if (length <= 0)
                    {
                        error = "native helper returned " + length;
                        return false;
                    }

                    packet = new byte[length];
                    Buffer.BlockCopy(output, 0, packet, 0, packet.Length);
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex.GetType().Name + ": " + ex.Message;
                    return false;
                }
            }

            private void Dispose(bool disposing)
            {
                if (handle != IntPtr.Zero)
                {
                    skype_session_free(handle);
                    handle = IntPtr.Zero;
                }
            }
        }

        private delegate int SessionCrypt(IntPtr session, byte[] input, int inputLength, byte[] output, int outputCapacity);

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr skype_session_create();

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void skype_session_free(IntPtr session);

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int skype_session_make_server_handshake(
            IntPtr session,
            byte[] sharedSecret,
            int sharedSecretLength,
            uint iv,
            ushort sequence,
            int garbageLength,
            byte[] output,
            int outputCapacity);

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int skype_session_decrypt_client_handshake(
            IntPtr session,
            byte[] sharedSecret,
            int sharedSecretLength,
            byte[] packet,
            int packetLength,
            byte[] output,
            int outputCapacity);

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int skype_session_decrypt_from_client(
            IntPtr session,
            byte[] packet,
            int packetLength,
            byte[] output,
            int outputCapacity);

        [DllImport("skype_rc4_helper.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int skype_session_encrypt_to_client(
            IntPtr session,
            byte[] packet,
            int packetLength,
            byte[] output,
            int outputCapacity);
    }
}
