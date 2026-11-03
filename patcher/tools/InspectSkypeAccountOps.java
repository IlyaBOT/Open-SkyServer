// Find account operation constants in the already rebuilt Skype 4.2 image.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class InspectSkypeAccountOps extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] targets = {0x139a, 0x139b, 0x139d, 0x1780, 0x1781, 0x1784, 0x1787, 0x139f, 0x2b08};
        int[] count = new int[targets.length];
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (monitor.isCancelled()) break;
            for (int op = 0; op < instruction.getNumOperands(); op++) {
                for (Object object : instruction.getOpObjects(op)) {
                    if (!(object instanceof Scalar)) continue;
                    long value = ((Scalar) object).getUnsignedValue();
                    for (int i = 0; i < targets.length; i++) {
                        if (value != targets[i] || count[i]++ >= 40) continue;
                        Function owner = getFunctionContaining(instruction.getAddress());
                        println(String.format("OP %04X AT %s OWNER %s : %s", targets[i],
                            instruction.getAddress(), owner == null ? "unknown" : owner.getEntryPoint(), instruction));
                    }
                }
            }
        }
        for (int i = 0; i < targets.length; i++)
            println(String.format("COUNT %04X %d", targets[i], count[i]));
    }
}
