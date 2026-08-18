package org.jarsentinel.detector.impl;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

/**
 * Heuristically identifies XOR-based bytecode string decryptors and anti-analysis payload concealment.
 */
public class ObfuscatedStringDetector implements Detector {

    @Override
    public String getId() {
        return "obfuscated-string";
    }

    @Override
    public String getName() {
        return "Obfuscation & XOR Decryptor Detector";
    }

    @Override
    public String getDescription() {
        return "Detects XOR encryption loops and dynamic string decryptor routines used to hide malware payloads.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.OBFUSCATION_MALICIOUS;
    }

    @Override
    public void scanClass(ClassNode classNode, ScanContext context) {
        if (org.jarsentinel.core.LibraryWhitelist.isWhitelistedPackage(classNode.name)) return;
        if (classNode.methods == null) return;

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null) continue;

            int xorCount = 0;
            int arrayStoreCount = 0;
            boolean hasLoop = false;
            int currentLine = -1;

            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LineNumberNode lnn) {
                    currentLine = lnn.line;
                } else if (insn.getOpcode() == Opcodes.IXOR) {
                    xorCount++;
                } else if (insn.getOpcode() == Opcodes.BASTORE || insn.getOpcode() == Opcodes.CASTORE) {
                    arrayStoreCount++;
                } else if (insn instanceof JumpInsnNode jump) {
                    // Check backward jump which indicates loop structure
                    if (method.instructions.indexOf(jump.label) < method.instructions.indexOf(jump)) {
                        hasLoop = true;
                    }
                }
            }

            // A method that has XOR operations inside a loop storing into a byte/char array is classic XOR decryptor
            if (xorCount > 0 && arrayStoreCount > 0 && hasLoop) {
                context.addFinding(Finding.builder()
                        .detectorName(getName())
                        .category(getCategory())
                        .severity(Severity.MEDIUM)
                        .title("XOR Bytecode String Decryptor Loop")
                        .description("Method contains a bytecode loop performing IXOR on char/byte arrays, typical of payload deobfuscators.")
                        .className(classNode.name)
                        .methodName(method.name)
                        .methodDescriptor(method.desc)
                        .lineNumber(currentLine)
                        .evidence("Pattern: IXOR (" + xorCount + "x) + ArrayStore (" + arrayStoreCount + "x) inside backward loop")
                        .remediation("Review the decrypted payload strings to ensure no covert C2 communication is happening.")
                        .build());
            }
        }
    }
}
