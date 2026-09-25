// Read selected strings and constant data near a Skype 4.2 call site.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;

public class InspectSkypeStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String value : getScriptArgs()) {
            Address address = toAddr(value);
            Data data = currentProgram.getListing().getDataContaining(address);
            println(address + " " + (data == null ? "undefined" : data.toString()));
        }
    }
}
