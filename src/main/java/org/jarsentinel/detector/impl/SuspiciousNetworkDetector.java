package org.jarsentinel.detector.impl;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.tree.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects hardcoded Discord webhooks, Telegram bot tokens, Pastebin C2 downloaders, and raw sockets.
 */
public class SuspiciousNetworkDetector implements Detector {

    private static final Pattern DISCORD_WEBHOOK_PATTERN = Pattern.compile(
            "https?://(?:canary\\.|ptb\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[a-zA-Z0-9_-]+"
    );

    private static final Pattern TELEGRAM_BOT_PATTERN = Pattern.compile(
            "https?://api\\.telegram\\.org/bot\\d+:[a-zA-Z0-9_-]+"
    );

    private static final List<String> PASTE_C2_HOSTS = List.of(
            "pastebin.com/raw/",
            "paste.ee/r/",
            "rentry.co/",
            "ghostbin.com",
            "hastebin.com/raw/"
    );

    private static final List<String> SUSPICIOUS_NETWORK_CLASSES = List.of(
            "java/net/Socket",
            "java/net/ServerSocket",
            "java/net/DatagramSocket"
    );

    @Override
    public String getId() {
        return "suspicious-network";
    }

    @Override
    public String getName() {
        return "Suspicious Network & C2 Detector";
    }

    @Override
    public String getDescription() {
        return "Detects hardcoded Discord webhooks, Telegram bot exfiltration, and C2 paste repositories.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.NETWORK_C2;
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
                } else if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    checkStringConstant(classNode, method, currentLine, s, context);
                } else if (insn instanceof MethodInsnNode minsn) {
                    checkMethodCall(classNode, method, minsn, currentLine, context);
                }
            }
        }
    }

    private void checkStringConstant(ClassNode classNode, MethodNode method, int line, String constant, ScanContext context) {
        // 1. Discord Webhook Exfiltration
        if (DISCORD_WEBHOOK_PATTERN.matcher(constant).find()) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.CRITICAL)
                    .title("Hardcoded Discord Webhook")
                    .description("Found active Discord Webhook endpoint used for data exfiltration.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("LDC \"" + constant + "\"")
                    .remediation("Remove hardcoded exfiltration webhooks immediately.")
                    .build());
        }

        // 2. Telegram Bot API
        if (TELEGRAM_BOT_PATTERN.matcher(constant).find()) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.CRITICAL)
                    .title("Hardcoded Telegram Bot Token / Exfiltration API")
                    .description("Found Telegram Bot API token used to dispatch stolen data or receive C2 commands.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("LDC \"" + constant + "\"")
                    .remediation("Revoke the Telegram bot token and remove command handlers.")
                    .build());
        }

        // 3. Pastebin / Rentry raw downloaders
        for (String pasteHost : PASTE_C2_HOSTS) {
            if (constant.toLowerCase(Locale.ROOT).contains(pasteHost)) {
                context.addFinding(Finding.builder()
                        .detectorName(getName())
                        .category(getCategory())
                        .severity(Severity.HIGH)
                        .title("C2 Paste Service URL (" + pasteHost + ")")
                        .description("Found reference to dynamic paste service often used to host secondary stages or payload configs.")
                        .className(classNode.name)
                        .methodName(method.name)
                        .methodDescriptor(method.desc)
                        .lineNumber(line)
                        .evidence("LDC \"" + constant + "\"")
                        .remediation("Do not load unverified dynamic payloads from paste hosting services.")
                        .build());
            }
        }
    }

    private void checkMethodCall(ClassNode classNode, MethodNode method, MethodInsnNode minsn, int line, ScanContext context) {
        if (SUSPICIOUS_NETWORK_CLASSES.contains(minsn.owner) && "<init>".equals(minsn.name)) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.LOW)
                    .title("Raw Socket Instantiation (" + minsn.owner + ")")
                    .description("Instantiated direct TCP/UDP socket. Common in network tools, but notable in modding.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("NEW " + minsn.owner + " -> <init>")
                    .remediation("Ensure raw socket connections are validated and expected in the application design.")
                    .build());
        }
    }
}
