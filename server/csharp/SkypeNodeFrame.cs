using System;
using System.Collections.Generic;
using System.IO;

namespace SkyServer
{
    internal sealed class SkypeNodeCommand
    {
        internal uint Code;
        internal byte Flags;
        internal ushort? RequestId;
        internal List<SkypeField> Fields;
    }

    // A node TCP frame can contain several commands. Their length excludes
    // the command varint, but includes the request ID when flags bit 1 is set.
    internal sealed class SkypeNodeFrame
    {
        internal ushort Sequence;
        internal bool IsAcknowledgment;
        internal readonly List<SkypeNodeCommand> Commands = new List<SkypeNodeCommand>();

        internal static SkypeNodeFrame Decode(byte[] packet)
        {
            if (packet == null || packet.Length < 4 || packet.Length > SkypeTcpFrameBuffer.MaximumFrameLength)
                throw new InvalidDataException("Invalid node frame size");
            int at = 0;
            uint length = ReadVarint(packet, ref at);
            if ((length >> 1) != packet.Length - at)
                throw new InvalidDataException("Node frame length mismatch");
            SkypeNodeFrame frame = new SkypeNodeFrame();
            if ((length & 1) != 0)
            {
                if (packet.Length - at != 3 || packet[at++] != 1)
                    throw new InvalidDataException("Unknown node control frame");
                frame.IsAcknowledgment = true;
                frame.Sequence = ReadSequence(packet, ref at);
                return frame;
            }
            frame.Sequence = ReadSequence(packet, ref at);
            while (at < packet.Length)
            {
                if (frame.Commands.Count == 64) throw new InvalidDataException("Too many node commands");
                uint bodyLength = ReadVarint(packet, ref at);
                uint encodedCommand = ReadVarint(packet, ref at);
                if (bodyLength > packet.Length - at) throw new InvalidDataException("Truncated node command");
                int end = at + (int)bodyLength;
                SkypeNodeCommand command = new SkypeNodeCommand();
                command.Code = encodedCommand >> 3;
                command.Flags = (byte)(encodedCommand & 7);
                if (command.Flags > 3) throw new InvalidDataException("Unsupported node command flags");
                if ((command.Flags & 2) != 0)
                {
                    if (end - at < 2) throw new InvalidDataException("Missing node request ID");
                    command.RequestId = ReadSequence(packet, ref at);
                }
                byte[] payload = new byte[end - at];
                Buffer.BlockCopy(packet, at, payload, 0, payload.Length);
                int consumed;
                command.Fields = SkypeBlobCodec.Decode(payload, out consumed);
                if (consumed != payload.Length) throw new InvalidDataException("Trailing node command data");
                frame.Commands.Add(command);
                at = end;
            }
            if (frame.Commands.Count == 0) throw new InvalidDataException("Empty node frame");
            return frame;
        }

        internal static byte[] Acknowledge(ushort sequence)
        {
            // Native 4.2 sender 00602C60: transport receipt, not an RPC success.
            return new byte[] { 7, 1, (byte)(sequence >> 8), (byte)sequence };
        }

        internal static byte[] Encode(ushort sequence, params SkypeNodeCommand[] commands)
        {
            if (commands == null || commands.Length == 0 || commands.Length > 64)
                throw new InvalidDataException("Invalid node command count");
            using (MemoryStream body = new MemoryStream())
            using (MemoryStream frame = new MemoryStream())
            {
                WriteSequence(body, sequence);
                foreach (SkypeNodeCommand command in commands)
                {
                    if (command == null || command.Code > 0x1fffffff || command.Flags > 3 ||
                        command.RequestId.HasValue != ((command.Flags & 2) != 0))
                        throw new InvalidDataException("Invalid node command header");
                    byte[] payload = SkypeBlobCodec.Encode(command.Fields);
                    WriteVarint(body, (uint)(payload.Length + (command.RequestId.HasValue ? 2 : 0)));
                    WriteVarint(body, (command.Code << 3) | command.Flags);
                    if (command.RequestId.HasValue) WriteSequence(body, command.RequestId.Value);
                    body.Write(payload, 0, payload.Length);
                    if (body.Length > SkypeTcpFrameBuffer.MaximumFrameLength - 3)
                        throw new InvalidDataException("Node frame too large");
                }
                WriteVarint(frame, (uint)body.Length << 1);
                body.Position = 0;
                body.CopyTo(frame);
                return frame.ToArray();
            }
        }

        private static ushort ReadSequence(byte[] data, ref int at)
        {
            if (data.Length - at < 2) throw new InvalidDataException("Truncated node sequence");
            ushort value = (ushort)((data[at] << 8) | data[at + 1]);
            at += 2;
            return value;
        }

        private static uint ReadVarint(byte[] data, ref int at)
        {
            uint value = 0;
            for (int shift = 0; shift < 35; shift += 7)
            {
                if (at >= data.Length) throw new InvalidDataException("Truncated node varint");
                byte next = data[at++];
                if (shift == 28 && next > 15) throw new InvalidDataException("Node varint overflow");
                value |= (uint)(next & 127) << shift;
                if ((next & 128) == 0) return value;
            }
            throw new InvalidDataException("Node varint too long");
        }

        private static void WriteVarint(Stream stream, uint value)
        {
            while (value >= 128) { stream.WriteByte((byte)(value | 128)); value >>= 7; }
            stream.WriteByte((byte)value);
        }

        private static void WriteSequence(Stream stream, ushort value)
        {
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }
    }
}
