using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace SkyServer
{
    internal static class NativeNodeDirectory
    {
        // One community directory owns all 2048 slots. No client is nominated
        // as a supernode. Native SupernodePool handler 00698AE0 expects command 8.
        internal static SkypeNodeCommand SlotReply(SkypeNodeCommand request, IPEndPoint local)
        {
            if (request.Code != 6) return null;
            bool hasSlot = false;
            foreach (SkypeField field in request.Fields) hasSlot |= field.Type == 0 && field.Id == 0;
            // 0/4 selects a capability-based pool, not a username slot. Leave
            // that unimplemented request alone without killing the node session.
            if (!hasSlot) return null;
            if (request.Flags != 2 || !request.RequestId.HasValue || request.Fields.Count != 2)
                throw new InvalidDataException("Invalid slot request header");
            uint slot = SkypeBlobCodec.Required(request.Fields, 0, 0).Number;
            uint count = SkypeBlobCodec.Required(request.Fields, 0, 5).Number;
            if (slot >= 2048 || count == 0 || count > 32)
                throw new InvalidDataException("Invalid directory slot or requested node count");
            if (local == null || local.Address.AddressFamily != AddressFamily.InterNetwork ||
                local.Address.Equals(IPAddress.Any) || local.Port == 0)
                throw new InvalidDataException("Missing concrete directory endpoint");
            byte[] endpoint = new byte[6];
            Buffer.BlockCopy(local.Address.GetAddressBytes(), 0, endpoint, 0, 4);
            endpoint[4] = (byte)(local.Port >> 8);
            endpoint[5] = (byte)local.Port;
            // get_blob.c/get_02_03_blob: repeated 5/6 with slot, total and 2/3 endpoints.
            return new SkypeNodeCommand { Code = 8, Flags = 3, RequestId = request.RequestId,
                Fields = new List<SkypeField> {
                    new SkypeField { Type = 5, Id = 6, Children = new List<SkypeField> {
                        new SkypeField { Type = 2, Id = 3, Bytes = endpoint },
                        new SkypeField { Type = 0, Id = 0, Number = slot },
                        new SkypeField { Type = 0, Id = 7, Number = 1 }
                    } }
                } };
        }
    }
}
