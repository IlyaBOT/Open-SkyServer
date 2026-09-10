// Decode only stage one in the Ghidra analysis database, not in Skype.exe.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class DecodeSkypeLoader extends GhidraScript {
    @Override
    public void run() throws Exception {
        byte[] expected = { (byte)0xfc, (byte)0xb8, 0x17, 0x58, 0x70, (byte)0x8c,
            (byte)0xb9, (byte)0xe0, (byte)0x92, 0x4f, 0 };
        byte[] actual = getBytes(toAddr(0x50f16e), expected.length);
        if (!java.util.Arrays.equals(actual, expected)) throw new Exception("Wrong loader signature");
        // The encrypted fallthrough is POPAD before decoding, not a real opcode.
        if (getByte(toAddr(0x50f195)) != 0x61) throw new Exception("Stage already decoded or unsupported file");
        clearListing(toAddr(0x4f92e0), toAddr(0x50f363));
        int key = 0x8c705817;
        for (long va = 0x4f92e0; va < 0x50f364; va++) {
            if (va == 0x50f16e) va += 0x27;
            Address at = toAddr(va);
            setByte(at, (byte)(getByte(at) ^ key));
            key = Integer.rotateLeft(key, 3);
        }
        println("STAGE1 decoded in analysis database only; next VA=0050f195");
    }
}
