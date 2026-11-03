// Locate caller references to selected strings in the unpacked Skype 4.2 image.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.nio.charset.StandardCharsets;

public class InspectSkypeStringRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        String[] needles = getScriptArgs();
        for (String needle : needles) {
            byte[] pattern = needle.getBytes(StandardCharsets.US_ASCII);
            Address cursor = currentProgram.getMinAddress();
            int matches = 0;
            while (cursor != null && matches < 20 && !monitor.isCancelled()) {
                Address found = memory.findBytes(cursor, pattern, null, true, monitor);
                if (found == null) break;
                matches++;
                println("STRING " + needle + " AT " + found);
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(found);
                int printed = 0;
                while (refs.hasNext() && printed++ < 30) {
                    Reference ref = refs.next();
                    Function owner = getFunctionContaining(ref.getFromAddress());
                    println("  REF " + ref.getFromAddress() + " OWNER " +
                        (owner == null ? "unknown" : owner.getEntryPoint() + " " + owner.getName()));
                }
                cursor = found.next();
            }
            println("COUNT " + needle + " " + matches);
        }
    }
}
