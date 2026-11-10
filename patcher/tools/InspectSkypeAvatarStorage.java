// Analysis-only corrections in a read-only Ghidra project; no EXE bytes change.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.FlowOverride;

public class InspectSkypeAvatarStorage extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address lock = toAddr("0063bf20");
        Address unlock = toAddr("0063bf70");
        for (Address helper : new Address[] { lock, unlock }) {
            Function function = getFunctionAt(helper);
            println("LOCK_NORETURN " + helper + " " + (function == null ? "unknown" : function.hasNoReturn()));
            if (function != null) function.setNoReturn(false);
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            for (String value : getScriptArgs()) {
                Address entry = toAddr(value);
                // Recover only a bounded code range after incorrectly terminal calls.
                for (long at = entry.getOffset(); at < entry.getOffset() + 0x600; at++) {
                    Instruction instruction = getInstructionAt(toAddr(at));
                    if (instruction == null || !instruction.getFlowType().isCall()) continue;
                    for (Address target : instruction.getFlows()) {
                        if (!target.equals(lock) && !target.equals(unlock)) continue;
                        instruction.setFlowOverride(FlowOverride.NONE);
                        disassemble(instruction.getMaxAddress().next());
                    }
                }
                disassemble(entry);
                Function function = getFunctionAt(entry);
                if (function == null) function = createFunction(entry, null);
                if (function == null) { println("NO_FUNCTION " + entry); continue; }
                CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
                println("FUNCTION " + entry + " BODY " + function.getBody());
                Instruction instruction = getInstructionAt(entry);
                int count = 0;
                while (instruction != null && function.getBody().contains(instruction.getAddress()) && count++ < 500) {
                    println(instruction.getAddress() + " " + instruction);
                    instruction = instruction.getNext();
                }
                decompiler.flushCache();
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
                if (result.decompileCompleted()) println(result.getDecompiledFunction().getC());
                else println("DECOMPILE_ERROR " + result.getErrorMessage());
            }
        } finally { decompiler.dispose(); }
    }
}
