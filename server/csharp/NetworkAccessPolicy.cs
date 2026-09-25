using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace SkyServer
{
    // Immutable startup snapshot. An empty closed list denies everyone, including localhost.
    internal sealed class NetworkAccessPolicy
    {
        private readonly List<byte[]> networks = new List<byte[]>();
        private readonly List<int> prefixes = new List<int>();
        internal static readonly NetworkAccessPolicy Open = new NetworkAccessPolicy();
        private bool closed;

        internal static NetworkAccessPolicy Load(string path)
        {
            NetworkAccessPolicy result = new NetworkAccessPolicy();
            result.closed = true;
            foreach (string line in File.ReadAllLines(path))
            {
                string entry = line.Split('#')[0].Trim();
                if (entry.Length == 0) continue;
                string[] parts = entry.Split('/');
                IPAddress address;
                int prefix = 32;
                if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out address) ||
                    address.AddressFamily != AddressFamily.InterNetwork ||
                    (parts.Length == 2 && (!Int32.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 32)))
                    throw new InvalidDataException("Invalid IPv4 allowlist entry: " + entry);
                result.networks.Add(address.GetAddressBytes());
                result.prefixes.Add(prefix);
            }
            return result;
        }

        internal bool Allows(IPAddress address)
        {
            if (!closed) return true;
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] candidate = address.GetAddressBytes();
            for (int i = 0; i < networks.Count; i++)
            {
                bool match = true;
                for (int b = 0; b < prefixes[i]; b++)
                    if ((candidate[b / 8] & (128 >> (b % 8))) != (networks[i][b / 8] & (128 >> (b % 8))))
                    { match = false; break; }
                if (match) return true;
            }
            return false;
        }

        internal bool Accept(TcpClient client)
        {
            if (Allows(((IPEndPoint)client.Client.RemoteEndPoint).Address)) return true;
            client.Close();
            return false;
        }
    }
}
