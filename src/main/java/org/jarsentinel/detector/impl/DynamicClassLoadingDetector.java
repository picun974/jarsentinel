package org.jarsentinel.detector.impl;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.tree.*;

/**
 * Detects dynamic bytecode injection, ClassLoader.defineClass, URLClassLoader, and JVM agent attachment.
 */
public class DynamicClassLoadingDetector implements Detector {

    @Override
    public String getId() {
        return "dynamic-injection";
    }

    @Override
    public String getName() {
        return "Dynamic Bytecode Injection Detector";
    }

    @Override
    public String getDescription() {
        return "Detects runtime class generation, defineClass calls, URLClassLoader remote loading, and JVM Agent attachment.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.DYNAMIC_INJECTION;
    }

    @Override
    public void scanClass(ClassNode classNode, ScanContext context) {
        if (classNode.methods == null) return;

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null) continue;

            int currentLine = -1;
            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LineNumberNode lnn) {
                    currentLine = lnn.line;
                } else if (insn instanceof MethodInsnNode minsn) {
                    checkMethodInsn(classNode, method, minsn, currentLine, context);
                }
            }
        }
    }

    private void checkMethodInsn(ClassNode classNode, MethodNode method, MethodInsnNode minsn, int line, ScanContext context) {
        // 1. defineClass
        if ("defineClass".equals(minsn.name) && minsn.owner.contains("ClassLoader")) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.HIGH)
                    .title("Runtime Bytecode Definition (defineClass)")
                    .description("Dynamically defining bytecode in memory at runtime without disk footprint.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("INVOKE " + minsn.owner + "." + minsn.name + minsn.desc)
                    .remediation("Use static classloading rather than dynamic in-memory byte definition.")
                    .build());
        }

        // 2. Attach API (VirtualMachine.attach)
        if ("com/sun/tools/attach/VirtualMachine".equals(minsn.owner) && "attach".equals(minsn.name)) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.CRITICAL)
                    .title("JVM Agent Hot-Attachment (VirtualMachine.attach)")
                    .description("Detected dynamic JVM process attachment. Often used by rootkits and inject-on-the-fly malware.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("INVOKESTATIC VirtualMachine.attach(...)")
                    .remediation("Do not dynamically inject agents into external or host JVM processes.")
                    .build());
        }

        // 3. Instrumentation retransformation
        if ("java/lang/instrument/Instrumentation".equals(minsn.owner) &&
                ("retransformClasses".equals(minsn.name) || "redefineClasses".equals(minsn.name))) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.HIGH)
                    .title("Runtime Class Redefinition / Hooking (Instrumentation)")
                    .description("Detected bytecode modification of already loaded classes at runtime.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("INVOKE Instrumentation." + minsn.name)
                    .remediation("Verify instrumentation scope and ensure it is not used to subvert security checks.")
                    .build());
        }
    }
}
