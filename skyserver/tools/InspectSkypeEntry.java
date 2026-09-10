// Read-only analysis of the imported original PE; never patches the installed file.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class InspectSkypeEntry extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address entry = toAddr(args.length == 0 ? "0050f16e" : args[0]);
        int count = args.length > 1 ? Integer.parseInt(args[1]) : 100;
        println("SKYPE_ENTRY " + entry);
        disassemble(entry);
        Function function = getFunctionAt(entry);
        if (function == null) function = createFunction(entry, null);
        Instruction instruction = getInstructionAt(entry);
        for (int i = 0; instruction != null && i < count; i++) {
            println(instruction.getAddress() + " " + instruction);
            instruction = instruction.getNext();
        }
        if (function != null) {
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
                if (result.decompileCompleted()) println(result.getDecompiledFunction().getC());
                else println("DECOMPILER: " + result.getErrorMessage());
            } finally { decompiler.dispose(); }
        }
    }
}
