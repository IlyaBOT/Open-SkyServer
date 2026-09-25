// Print pointer targets in an existing Skype 4.2 vtable.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class InspectSkypeVtable extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address base = toAddr(args[0]);
        int count = args.length > 1 ? Integer.parseInt(args[1]) : 20;
        if (count < 1 || count > 128) throw new IllegalArgumentException("count must be 1..128");
        for (int index = 0; index < count; index++) {
            Address slot = base.add(index * 4L);
            Address target = toAddr(Integer.toUnsignedLong(getInt(slot)));
            Function function = getFunctionContaining(target);
            println(String.format("%02d %s -> %s %s", index, slot, target,
                function == null ? "unknown" : function.getEntryPoint()));
        }
    }
}
