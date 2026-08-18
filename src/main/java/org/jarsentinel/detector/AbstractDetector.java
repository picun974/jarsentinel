package org.jarsentinel.detector;

import org.jarsentinel.core.LibraryWhitelist;
import org.jarsentinel.core.ScanContext;
import org.objectweb.asm.tree.*;

/**
 * Convenient base class providing template iteration for bytecode visitors.
 */
public abstract class AbstractDetector implements Detector {

    @Override
    public void scanClass(ClassNode classNode, ScanContext context) {
        if (LibraryWhitelist.isWhitelistedPackage(classNode.name)) return;
        if (classNode.methods == null) return;

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null) continue;

            int currentLine = -1;
            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LineNumberNode lnn) {
                    currentLine = lnn.line;
                }
                visitInstruction(classNode, method, insn, currentLine, context);
            }
        }
    }

    protected void visitInstruction(ClassNode classNode, MethodNode method, AbstractInsnNode insn, int line, ScanContext context) {
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String str) {
            visitStringConstant(classNode, method, line, str, context);
        } else if (insn instanceof MethodInsnNode minsn) {
            visitMethodInsn(classNode, method, line, minsn, context);
        } else if (insn instanceof FieldInsnNode finsn) {
            visitFieldInsn(classNode, method, line, finsn, context);
        }
    }

    protected void visitStringConstant(ClassNode classNode, MethodNode method, int line, String str, ScanContext context) {
        // Override in subclass
    }

    protected void visitMethodInsn(ClassNode classNode, MethodNode method, int line, MethodInsnNode minsn, ScanContext context) {
        // Override in subclass
    }

    protected void visitFieldInsn(ClassNode classNode, MethodNode method, int line, FieldInsnNode finsn, ScanContext context) {
        // Override in subclass
    }
}
