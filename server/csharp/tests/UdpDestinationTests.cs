using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SkyServer;

internal static class UdpDestinationTests
{
    internal static void Run()
    {
        List<IPAddress> addresses = new List<IPAddress> { IPAddress.Loopback };
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
                if (unicast.Address.AddressFamily == AddressFamily.InterNetwork && !addresses.Contains(unicast.Address))
                    addresses.Add(unicast.Address);
        }
        using (UdpClient receiver = ProbeUdpServer.BindWithPacketInformation(new IPEndPoint(IPAddress.Any, 0)))
        {
            receiver.Client.ReceiveTimeout = 3000;
            int port = ((IPEndPoint)receiver.Client.LocalEndPoint).Port;
            foreach (IPAddress address in addresses)
            {
                using (UdpClient sender = new UdpClient(new IPEndPoint(address, 0)))
                {
                    byte[] request = { 0x53, 0x4b, 0x59 };
                    // Queue the packet before the first receive, exercising the
                    // pre-bind PacketInformation requirement on Windows.
                    sender.Send(request, request.Length, new IPEndPoint(address, port));
                    byte[] buffer = new byte[32];
                    SocketFlags flags = SocketFlags.None;
                    EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    IPPacketInformation info;
                    int read = receiver.Client.ReceiveMessageFrom(buffer, 0, buffer.Length, ref flags, ref remote, out info);
                    if (read != request.Length || !info.Address.Equals(address) ||
                        !((IPEndPoint)remote).Address.Equals(address) || buffer[0] != 0x53)
                        throw new Exception("UDP destination/source information mismatch for " + address);
                }
            }
        }
        Console.WriteLine("PASS UDP wildcard destination tests for {0} local IPv4 addresses", addresses.Count);
    }
}
