// Inspect callers and nearby named data for one Skype 4.2 address.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class InspectSkypeCallers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address target = toAddr(args[0]);
        int limit = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        println("TARGET " + target);
        Data data = currentProgram.getListing().getDataAt(target);
        if (data != null) println("DATA " + data + " VALUE " + data.getValue());
        Instruction at = currentProgram.getListing().getInstructionAt(target);
        if (at != null) println("INSTRUCTION " + at);
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
        int count = 0;
        while (refs.hasNext() && count < limit) {
            Reference ref = refs.next();
            Function owner = getFunctionContaining(ref.getFromAddress());
            Instruction instruction = getInstructionContaining(ref.getFromAddress());
            println("REF " + ref.getFromAddress() + " OWNER " +
                (owner == null ? "unknown" : owner.getEntryPoint()) + " " + instruction);
            count++;
        }
        Function function = getFunctionContaining(target);
        if (function == null && at != null && "PUSH".equals(at.getMnemonicString()) &&
                "EBP".equals(at.getDefaultOperandRepresentation(0))) {
            function = createFunction(target, null);
            println("CREATED FUNCTION " + (function == null ? "failed" : function.getEntryPoint()));
        }
        if (function != null) {
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result.decompileCompleted()) println("DECOMPILE " + function.getEntryPoint() + "\n" + result.getDecompiledFunction().getC());
                else println("DECOMPILE ERROR " + result.getErrorMessage());
            } finally { decompiler.dispose(); }
        }
    }
}
