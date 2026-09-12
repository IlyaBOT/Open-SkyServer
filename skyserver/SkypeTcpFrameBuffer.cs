using System;
using System.Collections.Generic;
using System.IO;

namespace SkyServer
{
    // Skype TCP packets have a base-128 length prefix whose low bit is a flag.
    // TCP read boundaries do not correspond to these packet boundaries.
    internal sealed class SkypeTcpFrameBuffer
    {
        internal const int MaximumFrameLength = 16384;
        private readonly List<byte> pending = new List<byte>();

        internal List<byte[]> Append(byte[] data, int offset, int count)
        {
            if (data == null || offset < 0 || count < 0 || offset > data.Length - count)
                throw new ArgumentException("Invalid stream chunk");
            List<byte[]> frames = new List<byte[]>();
            for (int i = offset; i < offset + count; i++)
            {
                pending.Add(data[i]);
                uint size = 0;
                int prefix = 0;
                for (; prefix < pending.Count && prefix < 3; prefix++)
                {
                    byte value = pending[prefix];
                    size |= (uint)(value & 127) << (7 * prefix);
                    if ((value & 128) == 0) { prefix++; break; }
                }
                if (prefix == 0 || (pending[prefix - 1] & 128) != 0)
                {
                    if (prefix >= 3) throw new InvalidDataException("Oversized Skype TCP length prefix");
                    continue;
                }
                int total = prefix + (int)(size >> 1);
                if (total <= prefix || total > MaximumFrameLength)
                    throw new InvalidDataException("Invalid Skype TCP frame size");
                if (pending.Count == total)
                {
                    frames.Add(pending.ToArray());
                    pending.Clear();
                }
            }
            return frames;
        }

        internal bool HasPartialFrame { get { return pending.Count != 0; } }
    }
}
