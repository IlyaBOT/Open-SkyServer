// Reproduce the decoded loader's descriptor/checksum operations in Ghidra only.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class DecodeSkypeDescriptor extends GhidraScript {
    @Override
    public void run() throws Exception {
        long base = 0x101b000L;
        if (getInt(toAddr(base + 4)) != 0x536ae5fc || getByte(toAddr(0x50f195)) != 0x50)
            throw new Exception("Expected original descriptor and decoded stage one");
        int value = getInt(toAddr(base));
        int count = (value ^ (value >>> 16)) & 0xffff;
        if (count != 0x204) throw new Exception("Unexpected loader checksum size");
        int key = 0;
        for (int i = 0; i < count; i++) key = (key * 2 + (getByte(toAddr(0x50f160 + i)) & 0xff)) ^ (key >>> 31);
        println("DESCRIPTOR key=" + Integer.toHexString(key));
        for (int i = 4; i < 0x88; i++) {
            key = Integer.rotateLeft(key, 3);
            Address at = toAddr(base + i);
            setByte(at, (byte)(getByte(at) ^ key));
        }
        for (int i = 0; i < 0x88; i += 4)
            println(String.format("DESCRIPTOR +%02x = %08x", i, getInt(toAddr(base + i))));
        long start = Integer.toUnsignedLong(getInt(toAddr(base + 0x14)));
        long end = Integer.toUnsignedLong(getInt(toAddr(base + 0x18)));
        if (start < 0x400000 || end <= start || end - start > 0x2000000)
            throw new Exception("Unexpected checksum range");
        int hash = 0xa9c35b72;
        for (long at = start; at < end; at++) {
            hash = (hash << 4) + (getByte(toAddr(at)) & 0xff);
            int high = hash & 0xf0000000;
            if (high != 0) hash ^= high >>> 24;
            hash &= ~high;
        }
        long target = Integer.toUnsignedLong(getInt(toAddr(base + 0x20)) ^ hash);
        println(String.format("STAGE2 range=%08x..%08x checksum=%08x target=%08x", start, end, hash, target));
        if (target < 0x400000 || target >= 0x1c88000) throw new Exception("Target outside image");
        runScript("InspectSkypeEntry.java", new String[] { Long.toHexString(target), "40" });
    }
}
