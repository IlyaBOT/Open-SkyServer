using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using SkyServer;

internal static class SessionLifetimeTests
{
    internal static void Run(SkyDatabase database)
    {
        byte[] packet = { 0x14, 0x25, 0x1c, 5, 0x82, 3, 0x25, 0x1b, 0x42, 0x2d, 3 };
        byte[] ack = { 7, 1, 0xc1, 0xd2 };
        for (int split = 1; split < packet.Length; split++)
        {
            SkypeTcpFrameBuffer framing = new SkypeTcpFrameBuffer();
            if (framing.Append(packet, 0, split).Count != 0 || !framing.HasPartialFrame)
                throw new Exception("Incomplete packet emitted");
            List<byte[]> frames = framing.Append(packet, split, packet.Length - split);
            if (frames.Count != 1 || BitConverter.ToString(frames[0]) != BitConverter.ToString(packet) || framing.HasPartialFrame)
                throw new Exception("Fragmented packet framing failed");
        }
        byte[] combined = new byte[packet.Length + ack.Length];
        Buffer.BlockCopy(packet, 0, combined, 0, packet.Length);
        Buffer.BlockCopy(ack, 0, combined, packet.Length, ack.Length);
        if (new SkypeTcpFrameBuffer().Append(combined, 0, combined.Length).Count != 2)
            throw new Exception("Coalesced packet framing failed");
        byte[] large = new byte[302];
        large[0] = 0xd8; large[1] = 4; // 600 >> 1 = 300 payload bytes.
        if (new SkypeTcpFrameBuffer().Append(large, 0, large.Length).Count != 1)
            throw new Exception("Multi-byte length prefix framing failed");
        bool rejected = false;
        try { new SkypeTcpFrameBuffer().Append(new byte[] { 255, 255, 255 }, 0, 3); }
        catch (InvalidDataException) { rejected = true; }
        if (!rejected) throw new Exception("Oversized length accepted");

        AuthProtocolServer server = new AuthProtocolServer(database, IPAddress.Loopback, 0, false, true);
        Exception failure = null;
        Thread worker = new Thread(delegate() { try { server.Run(); } catch (Exception ex) { failure = ex; } });
        worker.IsBackground = true;
        worker.Start();
        try
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(5);
            while (server.ListeningEndpoint == null && DateTime.UtcNow < deadline) Thread.Sleep(10);
            IPEndPoint endpoint = server.ListeningEndpoint;
            if (endpoint == null) throw new Exception("Auth test server failed to start", failure);
            using (TcpClient idle = new TcpClient())
            using (TcpClient active = new TcpClient())
            {
                idle.Connect(endpoint);
                active.Connect(endpoint);
                active.ReceiveTimeout = 3000;
                byte[] hello = new byte[48]; hello[47] = 2;
                active.GetStream().Write(hello, 0, hello.Length);
                if (active.GetStream().ReadByte() < 0) throw new Exception("Idle connection blocked second auth client");
            }
        }
        finally
        {
            server.Stop();
            if (!worker.Join(5000)) throw new Exception("Auth listener did not stop");
        }
        if (failure != null) throw new Exception("Auth concurrency failure", failure);
        Console.WriteLine("PASS fragmented/coalesced TCP framing, limits, concurrent auth with idle socket, listener shutdown");
    }
}
