package org.jarsentinel.detector.impl;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Detects command execution, shell spawning (cmd.exe, PowerShell, bash), and downloader utilities.
 */
public class ProcessExecutionDetector implements Detector {

    private static final List<String> DANGEROUS_COMMANDS = List.of(
            "powershell",
            "powershell.exe",
            "cmd.exe",
            "cmd /c",
            "wscript",
            "cscript",
            "certutil",
            "certutil.exe",
            "bitsadmin",
            "/bin/sh",
            "/bin/bash",
            "curl ",
            "wget ",
            "reg add",
            "schtasks /create"
    );

    @Override
    public String getId() {
        return "process-exec";
    }

    @Override
    public String getName() {
        return "Process & Shell Execution Detector";
    }

    @Override
    public String getDescription() {
        return "Detects invocations of Runtime.exec, ProcessBuilder, and execution of system shells and download utilities.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.PROCESS_EXECUTION;
    }

    @Override
    public void scanClass(ClassNode classNode, ScanContext context) {
        if (classNode.methods == null) return;

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null) continue;

            int currentLine = -1;
            List<String> nearbyStringConstants = new ArrayList<>();

            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LineNumberNode lnn) {
                    currentLine = lnn.line;
                } else if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    nearbyStringConstants.add(s);
                } else if (insn instanceof MethodInsnNode minsn) {
                    checkMethodCall(classNode, method, minsn, currentLine, nearbyStringConstants, context);
                }
            }
        }
    }

    private void checkMethodCall(ClassNode classNode, MethodNode method, MethodInsnNode minsn,
                                 int line, List<String> nearbyConstants, ScanContext context) {
        boolean isRuntimeExec = "java/lang/Runtime".equals(minsn.owner) && "exec".equals(minsn.name);
        boolean isProcessBuilderStart = "java/lang/ProcessBuilder".equals(minsn.owner) && "start".equals(minsn.name);
        boolean isProcessBuilderInit = "java/lang/ProcessBuilder".equals(minsn.owner) && "<init>".equals(minsn.name);

        if (isRuntimeExec || isProcessBuilderStart || isProcessBuilderInit) {
            // Check if any dangerous command strings are present in this method
            Optional<String> matchedCommand = nearbyConstants.stream()
                    .filter(c -> DANGEROUS_COMMANDS.stream().anyMatch(dc -> c.toLowerCase(Locale.ROOT).contains(dc)))
                    .findFirst();

            Severity severity = matchedCommand.isPresent() ? Severity.CRITICAL : Severity.HIGH;
            String title = matchedCommand.isPresent()
                    ? "Malicious Command Execution (" + matchedCommand.get() + ")"
                    : "Native Process Execution";

            String evidence = "Invoked " + minsn.owner + "." + minsn.name + minsn.desc;
            if (matchedCommand.isPresent()) {
                evidence += " with payload: \"" + matchedCommand.get() + "\"";
            }

            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(severity)
                    .title(title)
                    .description("Detected system process spawning via " + minsn.owner + "." + minsn.name +
                            (matchedCommand.isPresent() ? ". Shell command string matched: " + matchedCommand.get() : ""))
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence(evidence)
                    .remediation("Avoid executing arbitrary native system processes from Java applications.")
                    .build());
        }
    }
}
