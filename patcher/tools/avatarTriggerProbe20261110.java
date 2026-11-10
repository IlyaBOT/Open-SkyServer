// Investigation only: run against a private project copy with -readOnly.
// @category SkyServer
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.FlowOverride;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

public class avatarTriggerProbe20261110 extends GhidraScript {
    private DecompInterface decompiler;

    private void refs(Address target) {
        println("REFS " + target);
        for (Reference ref : getReferencesTo(target)) {
            Function owner = getFunctionContaining(ref.getFromAddress());
            println(ref + " OWNER=" + (owner == null ? "unknown" : owner.getEntryPoint()));
        }
    }

    private void near(Address at, int before, int after) {
        Instruction ins = getInstructionContaining(at);
        if (ins == null) { disassemble(at); ins = getInstructionAt(at); }
        if (ins == null) { println("NO_INSTRUCTION " + at); return; }
        for (int i = 0; i < before && ins.getPrevious() != null; i++) ins = ins.getPrevious();
        for (int i = 0; i < before + after && ins != null; i++, ins = ins.getNext())
            println(ins.getAddress() + " " + ins);
    }

    private void function(Address entry) throws Exception {
        for (long i = 0; i < 0x4000; i++) {
            Instruction ins = getInstructionAt(entry.add(i));
            if (ins == null || !ins.getFlowType().isCall()) continue;
            for (Address target : ins.getFlows()) {
                if (target.equals(toAddr("0063bf20")) || target.equals(toAddr("0063bf70"))) {
                    ins.setFlowOverride(FlowOverride.NONE);
                    disassemble(ins.getMaxAddress().next());
                }
            }
        }
        disassemble(entry);
        Function f = getFunctionAt(entry);
        if (f == null) f = createFunction(entry, null);
        if (f == null) { println("NO_FUNCTION " + entry); return; }
        CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
        println("FUNCTION " + entry + " BODY=" + f.getBody());
        refs(entry);
        decompiler.flushCache();
        DecompileResults result = decompiler.decompileFunction(f, 90, monitor);
        if (result.decompileCompleted()) println(result.getDecompiledFunction().getC());
        else println("DECOMPILE_ERROR " + result.getErrorMessage());
    }

    @Override public void run() throws Exception {
        println("PROGRAM " + currentProgram.getName() + " SHA256=" + currentProgram.getExecutableSHA256());
        for (String value : new String[] { "0063bf20", "0063bf70" }) {
            Function f = getFunctionAt(toAddr(value));
            if (f != null) f.setNoReturn(false);
        }
        decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            for (String arg : getScriptArgs()) {
                String[] parts = arg.split(":");
                if (parts[0].equals("verify")) {
                    Address at = toAddr(parts[1]);
                    int count = Integer.decode(parts[2]);
                    byte[] canonical = Files.readAllBytes(Paths.get("I:/Open-SkyServer/patcher/diagnostics/192.168.52.34.image.bin"));
                    byte[] expected = Arrays.copyOfRange(canonical, (int)(at.getOffset() - 0x400000L), (int)(at.getOffset() - 0x400000L) + count);
                    byte[] actual = getBytes(at, count);
                    String hash = java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(actual));
                    println("VERIFY " + at + " LENGTH=" + count + " EQUAL=" + Arrays.equals(expected, actual) + " SHA256=" + hash);
                } else if (parts[0].equals("func")) function(toAddr(parts[1]));
                else if (parts[0].equals("refs")) refs(toAddr(parts[1]));
                else if (parts[0].equals("near")) near(toAddr(parts[1]), Integer.parseInt(parts[2]), Integer.parseInt(parts[3]));
                else if (parts[0].equals("table")) {
                    Address base = toAddr(parts[1]);
                    for (int i = 0; i < Integer.parseInt(parts[2]); i++) {
                        Address at = base.add(i * 4L);
                        println("SLOT " + at + " -> " + Integer.toHexString(getInt(at)));
                    }
                } else if (parts[0].equals("scan235")) {
                    InstructionIterator it = currentProgram.getListing().getInstructions(true);
                    int count = 0;
                    while (it.hasNext() && !monitor.isCancelled()) {
                        Instruction ins = it.next();
                        if (ins.toString().contains("0x235]")) {
                            Function f = getFunctionContaining(ins.getAddress());
                            println("FIELD235 " + ins.getAddress() + " " + ins + " OWNER=" + (f == null ? "unknown" : f.getEntryPoint()));
                            if (++count >= 250) break;
                        }
                    }
                }
            }
        } finally { decompiler.dispose(); }
    }
}
