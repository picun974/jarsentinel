package org.jarsentinel.detector.impl;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.tree.*;

import java.util.List;

/**
 * Detects dangerous reflection bypasses, Unsafe instantiation, and security manager evasion.
 */
public class ReflectionAbuseDetector implements Detector {

    private static final List<String> DANGEROUS_INTERNAL_PACKAGES = List.of(
            "sun/misc/Unsafe",
            "jdk/internal/misc/Unsafe",
            "sun/reflect",
            "java/lang/invoke/MethodHandles$Lookup"
    );

    @Override
    public String getId() {
        return "reflection-abuse";
    }

    @Override
    public String getName() {
        return "Reflection & Unsafe Abuse Detector";
    }

    @Override
    public String getDescription() {
        return "Detects direct access to sun.misc.Unsafe, setAccessible(true) bypasses, and private reflection attacks.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.REFLECTION_ABUSE;
    }

    @Override
    public void scanClass(ClassNode classNode, ScanContext context) {
        if (org.jarsentinel.core.LibraryWhitelist.isWhitelistedPackage(classNode.name)) return;
        if (classNode.methods == null) return;

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null) continue;

            int currentLine = -1;
            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LineNumberNode lnn) {
                    currentLine = lnn.line;
                } else if (insn instanceof FieldInsnNode finsn) {
                    checkFieldInsn(classNode, method, finsn, currentLine, context);
                } else if (insn instanceof MethodInsnNode minsn) {
                    checkMethodInsn(classNode, method, minsn, currentLine, context);
                }
            }
        }
    }

    private void checkFieldInsn(ClassNode classNode, MethodNode method, FieldInsnNode finsn, int line, ScanContext context) {
        if ("sun/misc/Unsafe".equals(finsn.owner) || "theUnsafe".equals(finsn.name)) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.HIGH)
                    .title("Direct Unsafe Field Access")
                    .description("Accessing sun.misc.Unsafe directly, allowing arbitrary memory manipulation and JVM crash vectors.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("GETFIELD/STATIC " + finsn.owner + "." + finsn.name)
                    .remediation("Use standard safe Java APIs (VarHandle, ByteBuffer, FFM API in Java 22+) instead of Unsafe.")
                    .build());
        }
    }

    private void checkMethodInsn(ClassNode classNode, MethodNode method, MethodInsnNode minsn, int line, ScanContext context) {
        if ("setAccessible".equals(minsn.name) &&
                ("java/lang/reflect/AccessibleObject".equals(minsn.owner) || "java/lang/reflect/Field".equals(minsn.owner) || "java/lang/reflect/Method".equals(minsn.owner))) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.MEDIUM)
                    .title("Reflection Accessibility Bypass (setAccessible)")
                    .description("Forcibly bypassing Java access controls to read/write private state.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("INVOKE " + minsn.owner + ".setAccessible(true)")
                    .remediation("Design components using public interfaces without breaking encapsulation.")
                    .build());
        }

        if (DANGEROUS_INTERNAL_PACKAGES.contains(minsn.owner)) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.MEDIUM)
                    .title("Internal JDK API Invocation (" + minsn.owner + ")")
                    .description("Targeting non-public internal JDK classes.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("INVOKE " + minsn.owner + "." + minsn.name)
                    .remediation("Migrate away from internal unsupported proprietary APIs.")
                    .build());
        }
    }
}
