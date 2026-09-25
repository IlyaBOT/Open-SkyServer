using System;
using System.Collections.Generic;
using System.IO;
using SkyServer;

internal static class SkypeNodeFrameTests
{
    internal static void Run()
    {
        byte[] captured = { 0x18, 0x34, 0xcd, 8, 0x32, 0x34, 0xcc, 0x42, 0x34, 0x1e, 0x8c, 0x63, 0x1e };
        SkypeNodeFrame native = SkypeNodeFrame.Decode(captured);
        Check(native.Sequence == 0x34cd && native.Commands.Count == 1, "captured frame");
        Check(native.Commands[0].Code == 6 && native.Commands[0].Flags == 2 &&
            native.Commands[0].RequestId == 0x34cc, "one-byte native command");
        byte[] bcmRequest = { 0x14, 0x25, 0x1c, 5, 0x82, 3, 0x25, 0x1b, 0x42, 0x2d, 3 };
        Check(SkypeNodeFrame.Decode(bcmRequest).Commands[0].Code == 48, "two-byte native command");

        SkypeNodeCommand advertisement = new SkypeNodeCommand { Code = 37, Flags = 1,
            Fields = new List<SkypeField> { new SkypeField { Type = 4, Id = 1, Bytes = new byte[300] } } };
        SkypeNodeCommand request = new SkypeNodeCommand { Code = 6, Flags = 2, RequestId = 65535,
            Fields = new List<SkypeField> { new SkypeField { Type = 0, Id = 0, Number = 7 } } };
        byte[] encoded = SkypeNodeFrame.Encode(0xabcd, advertisement, request);
        SkypeNodeFrame multi = SkypeNodeFrame.Decode(encoded);
        Check(multi.Sequence == 0xabcd && multi.Commands.Count == 2, "multi-command frame");
        Check(multi.Commands[0].Fields[0].Bytes.Length == 300 && !multi.Commands[0].RequestId.HasValue &&
            multi.Commands[1].RequestId == 65535 && multi.Commands[1].Fields[0].Number == 7, "multi-byte lengths and request ID");
        for (int split = 1; split < encoded.Length; split++)
        {
            SkypeTcpFrameBuffer buffer = new SkypeTcpFrameBuffer();
            Check(buffer.Append(encoded, 0, split).Count == 0, "partial large frame");
            List<byte[]> frames = buffer.Append(encoded, split, encoded.Length - split);
            Check(frames.Count == 1 && SkypeNodeFrame.Decode(frames[0]).Commands.Count == 2, "fragmented large frame");
        }
        byte[] receipt = SkypeNodeFrame.Acknowledge(0xabcd);
        Check(BitConverter.ToString(receipt) == "07-01-AB-CD", "native transport acknowledgment");
        SkypeNodeFrame ack = SkypeNodeFrame.Decode(receipt);
        Check(ack.IsAcknowledgment && ack.Sequence == 0xabcd && ack.Commands.Count == 0, "ack is not a command");
        Reject(new byte[] { 7, 2, 0, 1 });
        Reject(new byte[] { 6, 0, 1, 0 });
        Reject(new byte[] { 8, 0, 1, 255, 255 });
        Reject(new byte[] { 10, 0, 1, 1, 0x32, 0 });
        for (int length = 0; length < encoded.Length; length++)
        {
            byte[] truncated = new byte[length];
            Buffer.BlockCopy(encoded, 0, truncated, 0, length);
            Reject(truncated);
        }
        bool badHeader = false;
        try { SkypeNodeFrame.Encode(1, new SkypeNodeCommand { Code = 6, Flags = 2, Fields = request.Fields }); }
        catch (InvalidDataException) { badHeader = true; }
        Check(badHeader, "request ID required by flags");
        Console.WriteLine("PASS native node frames: captured 42, multi-command 41, variable lengths, fragmentation, transport ACK and malformed input");
    }

    private static void Reject(byte[] packet)
    {
        try { SkypeNodeFrame.Decode(packet); }
        catch (InvalidDataException) { return; }
        throw new Exception("Malformed node frame accepted");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception("Node framing: " + message);
    }
}
