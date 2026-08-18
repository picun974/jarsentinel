package org.jarsentinel.detector.impl;

import org.jarsentinel.core.LibraryWhitelist;
import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Detects HWID tracking, machine fingerprinting, and Anti-VM / Anti-Debug analysis evasion techniques.
 */
public class HwidAntiAnalysisDetector implements Detector {

    private static final List<String> HWID_FINGERPRINT_STRINGS = List.of(
            "wmic csproduct get uuid",
            "wmic bios get serialnumber",
            "wmic baseboard get serialnumber",
            "wmic diskdrive get serialnumber",
            "get-wmiobject win32_computersystemproduct",
            "getmac",
            "systeminfo",
            "reg query \"hklm\\hardware\\description\\system\\centralprocessor\""
    );

    private static final List<String> ANTI_DEBUG_VM_STRINGS = List.of(
            "wireshark",
            "x64dbg",
            "x32dbg",
            "processhacker",
            "cheatengine",
            "charles",
            "fiddler",
            "vboxguest",
            "vmtoolsd",
            "qemu",
            "hyper-v"
    );

    @Override
    public String getId() {
        return "hwid-anti-analysis";
    }

    @Override
    public String getName() {
        return "HWID & Anti-Analysis Detector";
    }

    @Override
    public String getDescription() {
        return "Identifies hardware fingerprinting (HWID grabbing) and anti-VM/anti-debugging detection routines.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.GENERAL_SUSPICIOUS;
    }

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
                } else if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    checkStringConstant(classNode, method, currentLine, s, context);
                }
            }
        }
    }

    private void checkStringConstant(ClassNode classNode, MethodNode method, int line, String constant, ScanContext context) {
        String lower = constant.toLowerCase(Locale.ROOT);

        // 1. HWID Fingerprinting
        for (String hwidPattern : HWID_FINGERPRINT_STRINGS) {
            if (lower.contains(hwidPattern)) {
                context.addFinding(Finding.builder()
                        .detectorName(getName())
                        .category(ThreatCategory.GENERAL_SUSPICIOUS)
                        .severity(Severity.HIGH)
                        .title("Hardware Identifier (HWID) Fingerprint Query")
                        .description("Querying system hardware IDs, motherboard/disk serials, or BIOS UUIDs for machine fingerprinting.")
                        .className(classNode.name)
                        .methodName(method.name)
                        .methodDescriptor(method.desc)
                        .lineNumber(line)
                        .evidence("LDC \"" + constant + "\"")
                        .remediation("Verify if hardware telemetry collection is authorized and complies with privacy guidelines.")
                        .build());
            }
        }

        // 2. Anti-VM & Anti-Debug
        for (String antiDebug : ANTI_DEBUG_VM_STRINGS) {
            if (lower.contains(antiDebug)) {
                context.addFinding(Finding.builder()
                        .detectorName(getName())
                        .category(ThreatCategory.GENERAL_SUSPICIOUS)
                        .severity(Severity.MEDIUM)
                        .title("Anti-VM / Anti-Analysis Indicator (" + antiDebug + ")")
                        .description("Inspecting running processes or system environment for virtual machines, debuggers, or traffic analyzers.")
                        .className(classNode.name)
                        .methodName(method.name)
                        .methodDescriptor(method.desc)
                        .lineNumber(line)
                        .evidence("LDC \"" + constant + "\"")
                        .remediation("Ensure anti-analysis tricks are not used to evade security sandbox inspection.")
                        .build());
            }
        }
    }
}
