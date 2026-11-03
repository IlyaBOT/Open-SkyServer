// Show call-site context around a selected Skype 4.2 instruction.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class InspectSkypeNearby extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Instruction target = getInstructionContaining(toAddr(args[0]));
        if (target == null) {
            println("No instruction at " + args[0]);
            return;
        }
        int before = args.length > 1 ? Integer.parseInt(args[1]) : 100;
        int after = args.length > 2 ? Integer.parseInt(args[2]) : 20;
        Instruction start = target;
        for (int i = 0; i < before && start.getPrevious() != null; i++) start = start.getPrevious();
        for (Instruction item = start; item != null; item = item.getNext()) {
            println(item.getAddress() + " " + item);
            if (item.getAddress().compareTo(target.getAddress()) >= 0 && after-- <= 0) break;
        }
    }
}
