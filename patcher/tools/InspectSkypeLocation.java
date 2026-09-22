// Inspect an existing instruction and its owning function without inventing an entry point.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class InspectSkypeLocation extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address location = toAddr(args[0]);
        int count = args.length > 1 ? Integer.parseInt(args[1]) : 100;
        Instruction instruction = getInstructionContaining(location);
        if (instruction == null) {
            disassemble(location);
            instruction = getInstructionAt(location);
        }
        for (int i = 0; instruction != null && i < count; i++) {
            println(instruction.getAddress() + " " + instruction);
            instruction = instruction.getNext();
        }
        Function function = getFunctionContaining(location);
        if (function == null) { println("No owning function at " + location); return; }
        println("OWNER " + function.getEntryPoint());
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
            if (result.decompileCompleted()) println(result.getDecompiledFunction().getC());
            else println("DECOMPILER: " + result.getErrorMessage());
        } finally { decompiler.dispose(); }
    }
}
