using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SkyServer
{
    internal sealed class ProbeUdpServer
    {
        private static readonly IPAddress[] HostCacheSeedAddresses = new IPAddress[]
        {
            IPAddress.Parse("91.190.218.40"),
            IPAddress.Parse("91.190.216.17"),
            IPAddress.Parse("65.55.223.25"),
            IPAddress.Parse("64.4.23.141"),
            IPAddress.Parse("111.221.74.33")
        };

        private static int nextUdpRandom = Environment.TickCount;

        private readonly IPAddress bindAddress;
        private readonly int[] ports;
        private volatile bool stopped;
        private readonly List<UdpClient> clients = new List<UdpClient>();

        public ProbeUdpServer(IPAddress bindAddress, int[] ports)
        {
            this.bindAddress = bindAddress;
            this.ports = ports;
        }

        public void Run()
        {
            for (int i = 0; i < ports.Length; i++)
            {
                try
                {
                    IPAddress listenAddress = GetPreferredBindAddress(ports[i]);
                    UdpClient client;
                    try
                    {
                        client = BindWithPacketInformation(new IPEndPoint(listenAddress, ports[i]));
                    }
                    catch (SocketException)
                    {
                        if (listenAddress.Equals(bindAddress))
                        {
                            throw;
                        }

                        client = BindWithPacketInformation(new IPEndPoint(bindAddress, ports[i]));
                        listenAddress = bindAddress;
                    }

                    clients.Add(client);
                    Thread thread = new Thread(ReceiveLoop);
                    thread.IsBackground = true;
                    thread.Start(client);
                    Console.WriteLine("udp probe listening on {0}:{1}", listenAddress, ports[i]);
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("udp probe could not bind {0}:{1}: {2}", bindAddress, ports[i], ex.Message);
                }
            }

            while (!stopped)
            {
                Thread.Sleep(250);
            }
        }

        public void Stop()
        {
            stopped = true;
            foreach (UdpClient client in clients)
            {
                client.Close();
            }
        }

        private void ReceiveLoop(object state)
        {
            UdpClient client = (UdpClient)state;
            byte[] buffer = new byte[65535];
            while (!stopped)
            {
                try
                {
                    EndPoint sender = new IPEndPoint(IPAddress.Any, 0);
                    SocketFlags flags = SocketFlags.None;
                    IPPacketInformation packetInfo;
                    int count = client.Client.ReceiveMessageFrom(buffer, 0, buffer.Length, ref flags, ref sender, out packetInfo);
                    IPEndPoint remote = (IPEndPoint)sender;
                    byte[] data = CopyRange(buffer, 0, count);
                    IPEndPoint local = (IPEndPoint)client.Client.LocalEndPoint;
                    IPAddress serverAddress = packetInfo.Address;
                    if (serverAddress == null || serverAddress.Equals(IPAddress.Any))
                    {
                        Console.WriteLine("udp probe missing destination packet information; packet ignored");
                        continue;
                    }
                    Console.WriteLine(
                        "udp probe {0} -> {1}:{2} bytes: {3}, data {4}",
                        remote,
                        serverAddress,
                        local.Port,
                        data.Length,
                        Hex(data, 0, Math.Min(data.Length, 64)));

                    byte[] response;
                    if (TryBuildUdpProbeReply(remote.Address, serverAddress, local.Port, data, out response))
                    {
                        client.Send(response, response.Length, remote);
                        Console.WriteLine(
                            "udp probe scripted {0}:{1} -> {2} b3-success bytes: {3}, data {4}",
                            serverAddress,
                            local.Port,
                            remote,
                            response.Length,
                            Hex(response, 0, Math.Min(response.Length, 64)));
                    }
                }
                catch (SocketException ex)
                {
                    if (!stopped)
                    {
                        Console.WriteLine("udp probe socket error: {0}", ex.SocketErrorCode);
                        if (ex.SocketErrorCode != SocketError.ConnectionReset) return;
                    }
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
            }
        }

        private IPAddress GetPreferredBindAddress(int port)
        {
            IPAddress seedAddress;
            if (bindAddress.Equals(IPAddress.Any) && TryGetHostCacheSeedAddress(port, out seedAddress))
            {
                return seedAddress;
            }

            return bindAddress;
        }

        internal static UdpClient BindWithPacketInformation(IPEndPoint endpoint)
        {
            UdpClient client = new UdpClient(AddressFamily.InterNetwork);
            try
            {
                // Set before bind so even the first queued datagram has a valid
                // destination. The bound address is 0.0.0.0 on a wildcard socket.
                client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
                client.Client.Bind(endpoint);
                return client;
            }
            catch
            {
                client.Close();
                throw;
            }
        }

        private static bool TryGetHostCacheSeedAddress(int port, out IPAddress address)
        {
            address = null;
            if (port < 40001 || port > 40036)
            {
                return false;
            }

            address = HostCacheSeedAddresses[(port - 40001) % HostCacheSeedAddresses.Length];
            return true;
        }

        private static bool TryBuildUdpProbeReply(IPAddress clientAddress, IPAddress serverAddress, int serverPort, byte[] request, out byte[] response)
        {
            response = null;
            if (request == null || request.Length < 12 || request[2] != 0x02)
            {
                return false;
            }

            ushort packetSequence = ReadUInt16BigEndian(request, 0);
            uint requestRandom = ReadUInt32BigEndian(request, 3);
            uint requestCrc = ReadUInt32BigEndian(request, 7);
            byte[] encrypted = CopyRange(request, 11, request.Length - 11);
            uint serverIp = IpToUInt32(serverAddress);
            uint selectedClientIp;
            uint requestIv;
            byte[] clear;

            if (!TryDecryptUdpPayload(
                clientAddress,
                serverIp,
                packetSequence,
                requestRandom,
                requestCrc,
                encrypted,
                out clear,
                out selectedClientIp,
                out requestIv))
            {
                Console.WriteLine(
                    "udp probe decrypt failed {0} -> {1}:{2} seq={3:X4} rnd={4:X8} expected-crc={5:X8}",
                    clientAddress,
                    serverAddress,
                    serverPort,
                    packetSequence,
                    requestRandom,
                    requestCrc);
                return false;
            }

            uint clearCrc = CalculateCrc32(clear, 0, clear.Length);
            Console.WriteLine(
                "udp probe decrypted {0}/{1} -> {2}:{3} seq={4:X4} rnd={5:X8} iv={6:X8} crc=ok expected={7:X8} actual={8:X8} clear {9}, ascii {10}",
                clientAddress,
                UInt32ToIpString(selectedClientIp),
                serverAddress,
                serverPort,
                packetSequence,
                requestRandom,
                requestIv,
                requestCrc,
                clearCrc,
                Hex(clear, 0, Math.Min(clear.Length, 96)),
                AsciiPreview(clear, 0, Math.Min(clear.Length, 96)));

            if (IsUdpOpenerProbe(clear))
            {
                Console.WriteLine(
                    "udp probe opener {0}:{1} -> {2}/{3} da01-no-reply seq={4:X4}",
                    serverAddress,
                    serverPort,
                    clientAddress,
                    UInt32ToIpString(selectedClientIp),
                    packetSequence);
                return false;
            }

            ushort clearSequence = ExtractClearSequence(clear, (ushort)(packetSequence - 1));
            byte[] replyClear = new byte[]
            {
                0x04,
                0xB3,
                0x04,
                (byte)(clearSequence >> 8),
                (byte)clearSequence,
                0x42,
                0x15
            };

            uint replyRandom = NextUdpRandom();
            response = BuildUdpPacket(serverIp, selectedClientIp, packetSequence, replyRandom, replyClear);
            Console.WriteLine(
                "udp probe clear {0}:{1} -> {2}/{3} b3-success seq={4:X4} clear-seq={5:X4} rnd={6:X8} clear {7}",
                serverAddress,
                serverPort,
                clientAddress,
                UInt32ToIpString(selectedClientIp),
                packetSequence,
                clearSequence,
                replyRandom,
                Hex(replyClear, 0, replyClear.Length));
            return true;
        }

        private static bool TryDecryptUdpPayload(
            IPAddress clientAddress,
            uint serverIp,
            ushort packetSequence,
            uint random,
            uint expectedCrc,
            byte[] encrypted,
            out byte[] clear,
            out uint selectedClientIp,
            out uint selectedIv)
        {
            uint[] clientCandidates = new uint[]
            {
                IpToUInt32(clientAddress),
                0,
                IpToUInt32(IPAddress.Loopback)
            };

            clear = null;
            selectedClientIp = 0;
            selectedIv = 0;

            for (int i = 0; i < clientCandidates.Length; i++)
            {
                uint candidateClientIp = clientCandidates[i];
                uint iv = BuildUdpIv(candidateClientIp, serverIp, packetSequence, random);
                byte[] candidateClear;
                string error;
                if (!SkypeNativeRc4.TryUdpCrypt(iv, encrypted, encrypted.Length, out candidateClear, out error))
                {
                    continue;
                }

                uint crc = CalculateCrc32(candidateClear, 0, candidateClear.Length);
                if (crc == expectedCrc)
                {
                    clear = candidateClear;
                    selectedClientIp = candidateClientIp;
                    selectedIv = iv;
                    return true;
                }
            }

            return false;
        }

        private static byte[] BuildUdpPacket(uint senderIp, uint receiverIp, ushort packetSequence, uint random, byte[] clear)
        {
            byte[] encrypted;
            string error;
            uint iv = BuildUdpIv(senderIp, receiverIp, packetSequence, random);
            if (!SkypeNativeRc4.TryUdpCrypt(iv, clear, clear.Length, out encrypted, out error))
            {
                throw new InvalidOperationException("UDP encrypt failed: " + error);
            }

            byte[] packet = new byte[11 + encrypted.Length];
            WriteUInt16BigEndian(packet, 0, packetSequence);
            packet[2] = 0x02;
            WriteUInt32BigEndian(packet, 3, random);
            WriteUInt32BigEndian(packet, 7, CalculateCrc32(clear, 0, clear.Length));
            Buffer.BlockCopy(encrypted, 0, packet, 11, encrypted.Length);
            return packet;
        }

        private static uint BuildUdpIv(uint firstIp, uint secondIp, ushort packetSequence, uint random)
        {
            uint[] words = new uint[] { firstIp, secondIp, packetSequence };
            return CalculateCrc32Words(words) ^ random;
        }

        private static ushort ExtractClearSequence(byte[] clear, ushort fallback)
        {
            for (int i = 0; i <= clear.Length - 4; i++)
            {
                if ((clear[i] == 0xE2 && clear[i + 1] == 0x02) ||
                    (clear[i] == 0xAA && clear[i + 1] == 0x03) ||
                    (clear[i] == 0xCA && clear[i + 1] == 0x04) ||
                    (clear[i] == 0xF2 && clear[i + 1] == 0x01))
                {
                    return ReadUInt16BigEndian(clear, i + 2);
                }
            }

            return fallback;
        }

        private static bool IsUdpOpenerProbe(byte[] clear)
        {
            return clear != null &&
                   clear.Length >= 5 &&
                   clear[1] == 0xDA &&
                   clear[2] == 0x01;
        }

        private static uint NextUdpRandom()
        {
            return unchecked((uint)Interlocked.Add(ref nextUdpRandom, (int)0x9E3779B9));
        }

        private static uint CalculateCrc32(byte[] data, int offset, int count)
        {
            uint z = 0xFFFFFFFF;
            for (int i = 0; i < count; i++)
            {
                z ^= data[offset + i];
                for (int j = 0; j < 8; j++)
                {
                    z = (z & 1) != 0 ? (z >> 1) ^ 0xEDB88320 : z >> 1;
                }
            }

            return z;
        }

        private static uint CalculateCrc32Words(uint[] words)
        {
            uint z = 0xFFFFFFFF;
            for (int i = 0; i < words.Length; i++)
            {
                z ^= words[i];
                for (int j = 0; j < 32; j++)
                {
                    z = (z & 1) != 0 ? (z >> 1) ^ 0xEDB88320 : z >> 1;
                }
            }

            return z;
        }

        private static uint IpToUInt32(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            if (bytes.Length != 4)
            {
                bytes = IPAddress.Loopback.GetAddressBytes();
            }

            return ((uint)bytes[0] << 24) |
                   ((uint)bytes[1] << 16) |
                   ((uint)bytes[2] << 8) |
                   bytes[3];
        }

        private static string UInt32ToIpString(uint address)
        {
            return String.Format(
                "{0}.{1}.{2}.{3}",
                (address >> 24) & 0xFF,
                (address >> 16) & 0xFF,
                (address >> 8) & 0xFF,
                address & 0xFF);
        }

        private static byte[] CopyRange(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }

        private static ushort ReadUInt16BigEndian(byte[] data, int offset)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        private static uint ReadUInt32BigEndian(byte[] data, int offset)
        {
            return ((uint)data[offset] << 24) |
                   ((uint)data[offset + 1] << 16) |
                   ((uint)data[offset + 2] << 8) |
                   data[offset + 3];
        }

        private static void WriteUInt16BigEndian(byte[] data, int offset, ushort value)
        {
            data[offset] = (byte)(value >> 8);
            data[offset + 1] = (byte)value;
        }

        private static void WriteUInt32BigEndian(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)(value >> 24);
            data[offset + 1] = (byte)(value >> 16);
            data[offset + 2] = (byte)(value >> 8);
            data[offset + 3] = (byte)value;
        }

        private static string Hex(byte[] bytes, int offset, int count)
        {
            char[] chars = new char[count * 3];
            int p = 0;
            for (int i = 0; i < count; i++)
            {
                byte b = bytes[offset + i];
                chars[p++] = GetHex((b >> 4) & 0xF);
                chars[p++] = GetHex(b & 0xF);
                chars[p++] = ' ';
            }

            return new string(chars).TrimEnd();
        }

        private static string AsciiPreview(byte[] bytes, int offset, int count)
        {
            StringBuilder builder = new StringBuilder(count);
            for (int i = 0; i < count; i++)
            {
                byte b = bytes[offset + i];
                builder.Append(b >= 0x20 && b <= 0x7E ? (char)b : '.');
            }

            return builder.ToString();
        }

        private static char GetHex(int value)
        {
            return (char)(value < 10 ? '0' + value : 'A' + value - 10);
        }
    }
}
