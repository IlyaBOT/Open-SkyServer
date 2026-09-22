using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using SkyServer;

internal static class DeploymentTests
{
    internal static void Run(string directory)
    {
        string path = Path.Combine(directory, "allowlist.txt");
        File.WriteAllText(path, "# exact and subnet\n127.0.0.1\n192.168.7.128/25 # friends\n");
        NetworkAccessPolicy policy = NetworkAccessPolicy.Load(path);
        Check(policy.Allows(IPAddress.Loopback), "exact IPv4");
        Check(policy.Allows(IPAddress.Parse("192.168.7.255")), "CIDR last address");
        Check(!policy.Allows(IPAddress.Parse("192.168.7.127")), "CIDR boundary");
        Check(!policy.Allows(IPAddress.IPv6Loopback), "IPv6 denied");
        File.WriteAllText(path, "");
        Check(!NetworkAccessPolicy.Load(path).Allows(IPAddress.Loopback), "empty denies localhost");
        File.WriteAllText(path, "192.168.0.1/33");
        Reject(delegate { NetworkAccessPolicy.Load(path); });
        Reject(delegate { NetworkAccessPolicy.Load(path + ".missing"); });
        var local = ServerOptions.Parse(new[] { "--host", "0.0.0.0" });
        Check(IPAddress.IsLoopback(local.ApiHost), "host never exposes API");
        var global = ServerOptions.Parse(new[] { "--mode", "global", "--advertise-ip", "203.0.113.8" });
        Check(global.AuthHost.Equals(IPAddress.Any) && IPAddress.IsLoopback(global.ApiHost), "global binds");
        var globalUdp = new ProbeUdpServer(IPAddress.Any, new[] { 40001 }, null, global.AdvertisedAddress);
        var selectedBind = (IPAddress)typeof(ProbeUdpServer).GetMethod("GetPreferredBindAddress", BindingFlags.NonPublic | BindingFlags.Instance)
            .Invoke(globalUdp, new object[] { 40001 });
        Check(selectedBind.Equals(IPAddress.Any), "Advertised mode must not bind legacy IP aliases");
        Reject(delegate { ServerOptions.Parse(new[] { "--mode", "global" }); });
        Reject(delegate { ServerOptions.Parse(new[] { "--closed" }); });
        Reject(delegate { ServerOptions.Parse(new[] { "--port", "65536" }); });
        Reject(delegate { ServerOptions.Parse(new[] { "--mode", "global", "--advertise-ip", "203.0.113.8", "--api-host", "0.0.0.0" }); });
        File.WriteAllText(path, "192.0.2.1\n");
        NetworkAccessPolicy deny = NetworkAccessPolicy.Load(path);
        int port = FreePort();
        var auth = new AuthProtocolServer(null, IPAddress.Loopback, port, false, false, null, deny);
        CheckTcpDenied(auth.Run, auth.Stop, port);
        port = FreePort();
        var api = new ApiServer(null, IPAddress.Loopback, port, deny);
        CheckTcpDenied(api.Run, api.Stop, port);
        port = FreePort();
        var probe = new TcpProbeServer(IPAddress.Loopback, new[] { port }, null, null, deny);
        CheckTcpDenied(probe.Run, probe.Stop, port);
        CheckUdp(NetworkAccessPolicy.Open, true);
        CheckUdp(deny, false);
        Console.WriteLine("PASS deployment allowlist and option validation");
    }
    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
    private static void CheckTcpDenied(ThreadStart run, Action stop, int port)
    {
        var thread = new Thread(run) { IsBackground = true };
        thread.Start();
        try
        {
            Thread.Sleep(200);
            using (var client = new TcpClient())
            {
                client.Connect(IPAddress.Loopback, port);
                client.ReceiveTimeout = 2000;
                Check(client.GetStream().ReadByte() == -1, "Denied TCP client received protocol data");
            }
        }
        finally { stop(); Check(thread.Join(3000), "Listener failed to stop"); }
    }
    private static void CheckUdp(NetworkAccessPolicy access, bool expectResponse)
    {
        int port;
        using (var reserve = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            port = ((IPEndPoint)reserve.Client.LocalEndPoint).Port;
        var server = new ProbeUdpServer(IPAddress.Loopback, new[] { port }, access);
        var thread = new Thread(server.Run) { IsBackground = true };
        thread.Start();
        try
        {
            Thread.Sleep(200);
            var flags = BindingFlags.NonPublic | BindingFlags.Static;
            uint ip = (uint)typeof(ProbeUdpServer).GetMethod("IpToUInt32", flags).Invoke(null, new object[] { IPAddress.Loopback });
            byte[] packet = (byte[])typeof(ProbeUdpServer).GetMethod("BuildUdpPacket", flags).Invoke(null,
                new object[] { ip, ip, (ushort)3, (uint)17, new byte[] { 4, 0xB3, 4, 0, 1, 0x42, 0x15 } });
            using (var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            {
                client.Client.ReceiveTimeout = 700;
                client.Send(packet, packet.Length, new IPEndPoint(IPAddress.Loopback, port));
                var remote = new IPEndPoint(IPAddress.Any, 0);
                bool received = false;
                try { received = client.Receive(ref remote).Length > 0; }
                catch (SocketException ex) { if (ex.SocketErrorCode != SocketError.TimedOut) throw; }
                Check(received == expectResponse, "UDP access filtering mismatch");
            }
        }
        finally { server.Stop(); Check(thread.Join(3000), "UDP listener failed to stop"); }
    }
    private static void Check(bool ok, string name) { if (!ok) throw new Exception(name); }
    private static void Reject(Action action)
    {
        try { action(); } catch (ArgumentException) { return; } catch (InvalidDataException) { return; } catch (IOException) { return; }
        throw new Exception("Invalid deployment configuration accepted");
    }
}
