using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Xml;

namespace SkyServer
{
    internal static class SkypeHostCache
    {
        public static List<IPEndPoint> ReadEndpoints(string sharedXmlPath)
        {
            List<IPEndPoint> endpoints = new List<IPEndPoint>();
            if (String.IsNullOrEmpty(sharedXmlPath) || !File.Exists(sharedXmlPath))
            {
                return endpoints;
            }

            XmlDocument document = new XmlDocument();
            document.Load(sharedXmlPath);
            XmlNode node = document.SelectSingleNode("/config/Lib/Connection/HostCache");
            if (node == null)
            {
                return endpoints;
            }

            byte[] bytes = DecodeHex(node.InnerText.Trim());
            Dictionary<string, IPEndPoint> unique = new Dictionary<string, IPEndPoint>(StringComparer.Ordinal);

            for (int i = 0; i <= bytes.Length - 10; i++)
            {
                if (bytes[i] != 0x41 || bytes[i + 1] != 0x05 || bytes[i + 2] != 0x02 || bytes[i + 3] != 0x00)
                {
                    continue;
                }

                byte[] addressBytes =
                {
                    bytes[i + 4],
                    bytes[i + 5],
                    bytes[i + 6],
                    bytes[i + 7]
                };

                int port = (bytes[i + 8] << 8) | bytes[i + 9];
                if (port <= 0 || port > 65535)
                {
                    continue;
                }

                IPAddress address = new IPAddress(addressBytes);
                string key = address + ":" + port;
                if (!unique.ContainsKey(key))
                {
                    unique.Add(key, new IPEndPoint(address, port));
                }
            }

            endpoints.AddRange(unique.Values);
            return endpoints;
        }

        private static byte[] DecodeHex(string hex)
        {
            if (String.IsNullOrEmpty(hex))
            {
                return new byte[0];
            }

            if ((hex.Length % 2) != 0)
            {
                throw new InvalidDataException("HostCache hex length is odd");
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return bytes;
        }
    }
}
