using System;
using System.Collections.Generic;
using System.Numerics;
using System.Runtime.InteropServices;

// Read-only RE helper. Never writes process memory or saves memory dumps.
public static class PublicConstantInspector
{
    private sealed class Pattern { public string Name; public byte[] Bytes; }
    private sealed class Anchor { public Pattern Pattern; public int Offset; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Region
    {
        public IntPtr Base, AllocationBase;
        public uint AllocationProtect;
        public UIntPtr Size;
        public uint State, Protect, Type;
    }
    [DllImport("kernel32", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32")]
    private static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out Region region, UIntPtr size);
    [DllImport("kernel32")]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, int size, out IntPtr read);
    [DllImport("kernel32")]
    private static extern bool CloseHandle(IntPtr handle);

    public static string[] Scan(int pid, byte[] login, byte[] credentials, string file)
    {
        List<Pattern> patterns = new List<Pattern>();
        AddLayouts(patterns, "login", login);
        AddLayouts(patterns, "credentials", credentials);
        int[] periods = { 0, 4, 8, 16 };
        List<Dictionary<uint, List<Anchor>>> indexes = new List<Dictionary<uint, List<Anchor>>>();
        foreach (int period in periods) indexes.Add(BuildIndex(patterns, period));
        HashSet<string> matches = new HashSet<string>();
        if (file != null)
        {
            byte[] data = System.IO.File.ReadAllBytes(file);
            ScanBytes(data, data.Length, 0, "file offset", indexes, periods, matches);
        }
        long examined = 0;
        if (pid > 0)
        {
            IntPtr process = OpenProcess(0x410, false, pid);
            if (process == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
            try
            {
                Region region;
                long cursor = 0;
                while (cursor < 0x80000000L && VirtualQueryEx(process, new IntPtr(cursor), out region,
                    new UIntPtr((uint)Marshal.SizeOf(typeof(Region)))).ToUInt64() != 0)
                {
                    long start = region.Base.ToInt64(), size = (long)region.Size.ToUInt64();
                    if (size <= 0 || start + size <= cursor) break;
                    cursor = start + size;
                    if (region.State != 0x1000 || (region.Protect & 0x101) != 0) continue;
                    for (long at = start; at < cursor; at += 1048576)
                    {
                        // The largest expanded modulus is 2048 bytes; overlap prevents boundary misses.
                        byte[] bytes = new byte[(int)Math.Min(1048576 + 4096, cursor - at)];
                        IntPtr read;
                        if (!ReadProcessMemory(process, new IntPtr(at), bytes, bytes.Length, out read)) continue;
                        int count = (int)read;
                        examined += count;
                        ScanBytes(bytes, count, at, "process VA", indexes, periods, matches);
                        Array.Clear(bytes, 0, bytes.Length);
                    }
                }
            }
            finally { CloseHandle(process); }
        }
        List<string> result = new List<string>(matches);
        result.Sort();
        result.Add("Layouts=" + patterns.Count + "; process read-only bytes examined=" + examined + "; matches=" + matches.Count);
        return result.ToArray();
    }

    private static void AddLayouts(List<Pattern> output, string name, byte[] bigEndian)
    {
        byte[] little = new byte[bigEndian.Length + 1];
        for (int i = 0; i < bigEndian.Length; i++) little[i] = bigEndian[bigEndian.Length - i - 1];
        BigInteger number = new BigInteger(little);
        HashSet<string> seen = new HashSet<string>();
        foreach (int digitBits in new[] { 8, 15, 16, 28, 30, 31, 32 })
        foreach (int storageBytes in new[] { 1, 2, 4, 8 })
        {
            if (storageBytes * 8 < digitBits) continue;
            List<ulong> digits = new List<ulong>();
            BigInteger value = number, mask = (BigInteger.One << digitBits) - 1;
            while (value > 0) { digits.Add((ulong)(value & mask)); value >>= digitBits; }
            foreach (bool reverseDigits in new[] { false, true })
            foreach (bool reverseBytes in new[] { false, true })
            {
                byte[] layout = new byte[digits.Count * storageBytes];
                for (int i = 0; i < digits.Count; i++)
                {
                    ulong digit = digits[reverseDigits ? digits.Count - i - 1 : i];
                    for (int j = 0; j < storageBytes; j++)
                        layout[i * storageBytes + (reverseBytes ? storageBytes - j - 1 : j)] = (byte)(digit >> (8 * j));
                }
                if (!seen.Add(Convert.ToBase64String(layout))) continue;
                output.Add(new Pattern { Name = name + ":radix" + digitBits + "/storage" + (storageBytes * 8) +
                    (reverseDigits ? "/MSD" : "/LSD") + (reverseBytes ? "/BE" : "/LE"), Bytes = layout });
            }
        }
    }

    private static uint Word(byte[] bytes, int i)
    {
        return (uint)(bytes[i] | bytes[i + 1] << 8 | bytes[i + 2] << 16 | bytes[i + 3] << 24);
    }

    private static Dictionary<uint, List<Anchor>> BuildIndex(List<Pattern> patterns, int period)
    {
        Dictionary<uint, List<Anchor>> index = new Dictionary<uint, List<Anchor>>();
        foreach (Pattern pattern in patterns)
        {
            int best = -1, score = -1;
            uint key = 0;
            for (int i = 0; i < pattern.Bytes.Length - 4 - period; i++)
            {
                uint v = Word(pattern.Bytes, i);
                if (period != 0) v ^= Word(pattern.Bytes, i + period);
                int s = 0;
                for (int j = 0; j < 4; j++) if (((v >> (8 * j)) & 255) != 0) s++;
                if (s > score) { best = i; score = s; key = v; }
                if (score == 4) break;
            }
            if (score <= 1) continue;
            List<Anchor> anchors;
            if (!index.TryGetValue(key, out anchors)) index.Add(key, anchors = new List<Anchor>());
            anchors.Add(new Anchor { Pattern = pattern, Offset = best });
        }
        return index;
    }

    private static void ScanBytes(byte[] data, int count, long address, string kind,
        List<Dictionary<uint, List<Anchor>>> indexes, int[] periods, HashSet<string> matches)
    {
        for (int k = 0; k < periods.Length; k++)
        {
            int period = periods[k];
            Dictionary<uint, List<Anchor>> index = indexes[k];
            for (int i = 0; i <= count - 4 - period; i++)
            {
                uint key = Word(data, i);
                if (period != 0) key ^= Word(data, i + period);
                List<Anchor> candidates;
                if (!index.TryGetValue(key, out candidates)) continue;
                foreach (Anchor anchor in candidates)
                {
                    byte[] expected = anchor.Pattern.Bytes;
                    int start = i - anchor.Offset;
                    if (start < 0 || start > count - expected.Length) continue;
                    bool good = true;
                    for (int j = 0; j < expected.Length; j++)
                    {
                        int mask = period == 0 ? 0 : data[start + j % period] ^ expected[j % period];
                        if ((data[start + j] ^ mask) != expected[j]) { good = false; break; }
                    }
                    if (good) matches.Add(kind + "=0x" + (address + start).ToString("X8") + " " +
                        anchor.Pattern.Name + " xorPeriod=" + period + " bytes=" + expected.Length);
                }
            }
        }
    }
}
