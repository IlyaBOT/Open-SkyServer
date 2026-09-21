using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using SkyServer;

internal static class NativeNodeDirectoryTests
{
    internal static void Run()
    {
        IPEndPoint local = new IPEndPoint(IPAddress.Parse("192.168.1.101"), 12350);
        foreach (uint slot in new uint[] { 0, 544, 1742, 2047 })
        {
            SkypeNodeCommand result = NativeNodeDirectory.SlotReply(Request(slot, 5), local);
            result = SkypeNodeFrame.Decode(SkypeNodeFrame.Encode(12, result)).Commands[0];
            if (result.Code != 8 || result.Flags != 3 || result.RequestId != 0x5727)
                throw new Exception("Slot reply header mismatch");
            List<SkypeField> fields = SkypeBlobCodec.Required(result.Fields, 5, 6).Children;
            if (SkypeBlobCodec.Required(fields, 0, 0).Number != slot || SkypeBlobCodec.Required(fields, 0, 7).Number != 1)
                throw new Exception("Slot identity/count mismatch");
            if (BitConverter.ToString(SkypeBlobCodec.Required(fields, 2, 3).Bytes) != "C0-A8-01-65-30-3E")
                throw new Exception("Directory advertised a different endpoint");
        }
        foreach (SkypeNodeCommand request in new[] { Request(2048, 1), Request(0, 0), Request(0, 33) })
        {
            bool rejected = false;
            try { NativeNodeDirectory.SlotReply(request, local); }
            catch (InvalidDataException) { rejected = true; }
            if (!rejected) throw new Exception("Invalid slot request accepted");
        }
        SkypeNodeCommand other = Request(0, 5);
        other.Fields[0].Id = 4;
        other.Fields[0].Number = 16;
        if (NativeNodeDirectory.SlotReply(other, local) != null) throw new Exception("Capability pool treated as username slot");
        other = Request(0, 5);
        other.Code = 37;
        if (NativeNodeDirectory.SlotReply(other, local) != null) throw new Exception("Non-slot command handled as slot lookup");
        Console.WriteLine("PASS native slot directory: bounds, actual endpoint, correlation, single-node count and wire round trip");
    }

    private static SkypeNodeCommand Request(uint slot, uint count)
    {
        return new SkypeNodeCommand { Code = 6, Flags = 2, RequestId = 0x5727,
            Fields = new List<SkypeField> { new SkypeField { Type = 0, Id = 0, Number = slot },
                new SkypeField { Type = 0, Id = 5, Number = count } } };
    }
}
