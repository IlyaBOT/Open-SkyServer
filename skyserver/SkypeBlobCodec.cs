using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace SkyServer
{
    internal sealed class SkypeField
    {
        public byte Type;
        public uint Id;
        public uint Number;
        public byte[] Bytes;
        public List<SkypeField> Children;
    }

    internal static class SkypeBlobCodec
    {
        internal static byte[] Encode(List<SkypeField> fields)
        {
            using (MemoryStream output = new MemoryStream())
            {
                int budget = 4096;
                WriteList(output, fields, 0, ref budget);
                return output.ToArray();
            }
        }

        private static void WriteList(MemoryStream output, List<SkypeField> fields, int depth, ref int budget)
        {
            if (fields == null || depth >= 8 || fields.Count > budget)
                throw new InvalidDataException("Invalid output blob list");
            budget -= fields.Count;
            output.WriteByte(0x41);
            WriteVarint(output, (uint)fields.Count);
            foreach (SkypeField field in fields)
            {
                if (field == null) throw new InvalidDataException("Null blob field");
                output.WriteByte(field.Type);
                WriteVarint(output, field.Id);
                byte[] bytes = field.Bytes;
                switch (field.Type)
                {
                    case 0: WriteVarint(output, field.Number); break;
                    case 1:
                    case 2:
                        if (bytes == null || bytes.Length != (field.Type == 1 ? 8 : 6))
                            throw new InvalidDataException("Invalid fixed-size blob");
                        WriteBytes(output, bytes);
                        break;
                    case 3:
                        if (bytes == null || Array.IndexOf(bytes, (byte)0) >= 0)
                            throw new InvalidDataException("Invalid blob string");
                        WriteBytes(output, bytes);
                        output.WriteByte(0);
                        break;
                    case 4:
                        if (bytes == null) throw new InvalidDataException("Missing blob bytes");
                        WriteVarint(output, (uint)bytes.Length);
                        WriteBytes(output, bytes);
                        break;
                    case 5: WriteList(output, field.Children, depth + 1, ref budget); break;
                    case 6:
                        if (bytes == null || bytes.Length % 4 != 0 || bytes.Length > 16384)
                            throw new InvalidDataException("Invalid blob words");
                        WriteVarint(output, (uint)(bytes.Length / 4));
                        for (int i = 0; i < bytes.Length; i += 4)
                            WriteVarint(output, BitConverter.ToUInt32(bytes, i));
                        break;
                    default: throw new InvalidDataException("Unknown output blob type");
                }
                if (output.Length > 16384) throw new InvalidDataException("Output blob size limit");
            }
        }

        private static void WriteBytes(MemoryStream output, byte[] bytes)
        {
            if (output.Length + bytes.Length > 16384) throw new InvalidDataException("Output blob size limit");
            output.Write(bytes, 0, bytes.Length);
        }

        private static void WriteVarint(Stream output, uint value)
        {
            while (value >= 128) { output.WriteByte((byte)(value | 128)); value >>= 7; }
            output.WriteByte((byte)value);
        }

        internal static List<SkypeField> Decode(byte[] input, out int consumed)
        {
            if (input == null || input.Length == 0 || input.Length > 16384)
                throw new InvalidDataException("Invalid 41/42 input size");
            if (input[0] == 0x41)
            {
                int at = 0, budget = 4096;
                List<SkypeField> fields = ReadList(input, ref at, 0, ref budget);
                consumed = at;
                return fields;
            }
            if (input[0] != 0x42) throw new InvalidDataException("Expected a 41/42 list");
            byte[] normalized = Normalize42(input, out consumed);
            int position = 0, fieldBudget = 4096;
            List<SkypeField> decoded = ReadList(normalized, ref position, 0, ref fieldBudget);
            if (position != normalized.Length) throw new InvalidDataException("Trailing normalized blob bytes");
            return decoded;
        }

        private static byte[] Normalize42(byte[] input, out int consumed)
        {
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "skype_blob_worker.exe");
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardInput = true;
            info.RedirectStandardOutput = true;
            using (Process worker = Process.Start(info))
            using (MemoryStream output = new MemoryStream())
            {
                Exception ioError = null;
                Thread io = new Thread(delegate()
                {
                    try
                    {
                        worker.StandardInput.BaseStream.Write(input, 0, input.Length);
                        worker.StandardInput.Close();
                        byte[] buffer = new byte[4096];
                        int count;
                        while ((count = worker.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            if (output.Length + count > 65540) throw new InvalidDataException("Blob worker output limit");
                            output.Write(buffer, 0, count);
                        }
                    }
                    catch (Exception ex) { ioError = ex; TryKill(worker); }
                });
                io.IsBackground = true;
                io.Start();
                bool finished = worker.WaitForExit(3000);
                if (!finished) { TryKill(worker); worker.WaitForExit(1000); }
                if (!io.Join(1000)) throw new IOException("Blob worker I/O did not stop");
                if (!finished) throw new InvalidDataException("Blob worker timeout");
                if (ioError != null) throw new InvalidDataException("Blob worker I/O failed", ioError);
                if (worker.ExitCode != 0) throw new InvalidDataException("Blob worker rejected packet (code " + worker.ExitCode + ")");
                byte[] framed = output.ToArray();
                if (framed.Length < 6) throw new InvalidDataException("Short blob worker output");
                consumed = BitConverter.ToInt32(framed, 0);
                if (consumed <= 0 || consumed > input.Length) throw new InvalidDataException("Invalid blob consumption count");
                byte[] result = new byte[framed.Length - 4];
                Buffer.BlockCopy(framed, 4, result, 0, result.Length);
                return result;
            }
        }

        private static void TryKill(Process process)
        {
            try { process.Kill(); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
        }

        private static List<SkypeField> ReadList(byte[] data, ref int at, int depth, ref int budget)
        {
            if (depth >= 8 || Byte(data, ref at) != 0x41) throw new InvalidDataException("Invalid nested 41 list");
            uint count = Varint(data, ref at);
            if (count > budget) throw new InvalidDataException("Too many blob fields");
            budget -= (int)count;
            List<SkypeField> fields = new List<SkypeField>();
            for (uint i = 0; i < count; i++)
            {
                SkypeField field = new SkypeField();
                field.Type = Byte(data, ref at);
                field.Id = Varint(data, ref at);
                switch (field.Type)
                {
                    case 0: field.Number = Varint(data, ref at); break;
                    case 1: field.Bytes = Take(data, ref at, 8); break;
                    case 2: field.Bytes = Take(data, ref at, 6); break;
                    case 3:
                        int end = Array.IndexOf(data, (byte)0, at);
                        if (end < at) throw new InvalidDataException("Unterminated blob string");
                        field.Bytes = Take(data, ref at, (uint)(end - at));
                        at++;
                        break;
                    case 4: field.Bytes = Take(data, ref at, Varint(data, ref at)); break;
                    case 5: field.Children = ReadList(data, ref at, depth + 1, ref budget); break;
                    case 6:
                        uint words = Varint(data, ref at);
                        if (words > 4096) throw new InvalidDataException("Too many blob words");
                        using (MemoryStream output = new MemoryStream())
                        {
                            for (uint word = 0; word < words; word++)
                            {
                                byte[] value = BitConverter.GetBytes(Varint(data, ref at));
                                output.Write(value, 0, value.Length);
                            }
                            field.Bytes = output.ToArray();
                        }
                        break;
                    default: throw new InvalidDataException("Unknown blob type");
                }
                fields.Add(field);
            }
            return fields;
        }

        internal static SkypeField Required(List<SkypeField> fields, byte type, uint id)
        {
            SkypeField found = null;
            foreach (SkypeField field in fields)
            {
                if (field.Id != id) continue;
                if (found != null || field.Type != type) throw new InvalidDataException("Duplicate or mistyped required login field");
                found = field;
            }
            if (found == null) throw new InvalidDataException("Required login field is absent");
            return found;
        }

        internal static uint Varint(byte[] data, ref int at)
        {
            uint value = 0;
            for (int shift = 0; shift <= 28; shift += 7)
            {
                byte b = Byte(data, ref at);
                if (shift == 28 && (b & 0xf0) != 0) throw new InvalidDataException("Blob varint overflow");
                value |= (uint)(b & 0x7f) << shift;
                if ((b & 0x80) == 0) return value;
            }
            throw new InvalidDataException("Invalid blob varint");
        }

        private static byte Byte(byte[] data, ref int at)
        {
            if (at < 0 || at >= data.Length) throw new InvalidDataException("Truncated blob");
            return data[at++];
        }

        private static byte[] Take(byte[] data, ref int at, uint length)
        {
            if (length > data.Length - at) throw new InvalidDataException("Blob length exceeds remaining input");
            byte[] result = new byte[(int)length];
            Buffer.BlockCopy(data, at, result, 0, result.Length);
            at += result.Length;
            return result;
        }
    }
}
