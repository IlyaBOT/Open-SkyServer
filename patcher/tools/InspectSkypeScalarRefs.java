// Find uses of protocol/property constants in analyzed Skype 4.2 instructions.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class InspectSkypeScalarRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long target = Long.decode(args[0]);
        int limit = args.length > 1 ? Integer.parseInt(args[1]) : 100;
        int count = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            for (int op = 0; op < instruction.getNumOperands(); op++) {
                for (Object object : instruction.getOpObjects(op)) {
                    if (!(object instanceof Scalar) || ((Scalar) object).getUnsignedValue() != target) continue;
                    Function owner = getFunctionContaining(instruction.getAddress());
                    if (count++ < limit) println(instruction.getAddress() + " OWNER " +
                        (owner == null ? "unknown" : owner.getEntryPoint()) + " " + instruction);
                }
            }
        }
        println("COUNT " + Long.toHexString(target) + " " + count);
    }
}
