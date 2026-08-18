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
 * Detects patterns associated with Discord, browser, Telegram, and crypto-wallet credential stealers.
 */
public class TokenGrabberDetector implements Detector {

    private static final List<String> DANGEROUS_TARGET_PATHS = List.of(
            "AppData/Roaming/discord/Local Storage/leveldb",
            "AppData/Roaming/discordcanary/Local Storage/leveldb",
            "AppData/Roaming/discordptb/Local Storage/leveldb",
            "AppData/Local/Google/Chrome/User Data",
            "AppData/Local/BraveSoftware/Brave-Browser/User Data",
            "AppData/Local/Microsoft/Edge/User Data",
            "AppData/Roaming/Opera Software/Opera Stable",
            "AppData/Roaming/Telegram Desktop/tdata",
            ".minecraft/launcher_accounts.json",
            ".minecraft/launcher_profiles.json",
            "Login Data",
            "Web Data",
            "Cookies"
    );

    private static final Pattern DISCORD_TOKEN_REGEX = Pattern.compile(
            "[a-zA-Z0-9_-]{24}\\.[a-zA-Z0-9_-]{6}\\.[a-zA-Z0-9_-]{27}|mfa\\.[a-zA-Z0-9_-]{84}"
    );

    @Override
    public String getId() {
        return "token-grabber";
    }

    @Override
    public String getName() {
        return "Credential & Token Stealer Detector";
    }

    @Override
    public String getDescription() {
        return "Identifies signatures of stealers targeting Discord tokens, browser sessions, Telegram, and crypto wallets.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.CREDENTIAL_STEALER;
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
                } else if (insn instanceof LdcInsnNode ldc) {
                    if (ldc.cst instanceof String str) {
                        context.addConstant(str);
                        checkStringConstant(classNode, method, currentLine, str, context);
                    }
                }
            }
        }
    }

    private void checkStringConstant(ClassNode classNode, MethodNode method, int line, String constant, ScanContext context) {
        String lower = constant.toLowerCase(Locale.ROOT);

        for (String target : DANGEROUS_TARGET_PATHS) {
            if (lower.contains(target.toLowerCase(Locale.ROOT))) {
                context.addFinding(Finding.builder()
                        .detectorName(getName())
                        .category(getCategory())
                        .severity(Severity.CRITICAL)
                        .title("Stealer Target Path Reference")
                        .description("Found explicit reference to sensitive credential directory: " + target)
                        .className(classNode.name)
                        .methodName(method.name)
                        .methodDescriptor(method.desc)
                        .lineNumber(line)
                        .evidence("LDC \"" + constant + "\"")
                        .remediation("Remove unauthorized access to system credentials and user profile data.")
                        .build());
            }
        }

        if (DISCORD_TOKEN_REGEX.matcher(constant).find() || lower.contains("discord.com/api/v9/users/@me")) {
            context.addFinding(Finding.builder()
                    .detectorName(getName())
                    .category(getCategory())
                    .severity(Severity.HIGH)
                    .title("Discord API Token or Auth Endpoint Inspection")
                    .description("Detected hardcoded Discord authorization pattern or user telemetry endpoint extraction.")
                    .className(classNode.name)
                    .methodName(method.name)
                    .methodDescriptor(method.desc)
                    .lineNumber(line)
                    .evidence("LDC \"" + constant + "\"")
                    .remediation("Do not bundle hardcoded auth tokens or steal client identities.")
                    .build());
        }
    }
}
