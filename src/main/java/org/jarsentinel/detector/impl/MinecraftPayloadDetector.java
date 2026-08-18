package org.jarsentinel.detector.impl;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.Locale;

/**
 * Detects malware patterns specific to the Minecraft modding and plugin ecosystem (e.g. Fractureiser signatures, session hijackers).
 */
public class MinecraftPayloadDetector implements Detector {

    private static final List<String> FRACTUREISER_INDICATORS = List.of(
            "dl.php",
            "files.php",
            "skyrage.de",
            "bytebin.lucko.me",
            "checkhost.to",
            "85.217.144.130",
            "107.189.3.101"
    );

    private static final List<String> SESSION_HIJACK_KEYWORDS = List.of(
            "getselectedprofile",
            "getauthenticatedtoken",
            "getsessiontoken",
            "yggdrasilauthenticationservice",
            "minecraftsession",
            "session.gettoken"
    );

    @Override
    public String getId() {
        return "minecraft-payload";
    }

    @Override
    public String getName() {
        return "Minecraft Ecosystem Threat Detector";
    }

    @Override
    public String getDescription() {
        return "Detects Fractureiser worm signatures, Minecraft session token hijackers, and malicious plugin backdoors.";
    }

    @Override
    public ThreatCategory getCategory() {
        return ThreatCategory.CREDENTIAL_STEALER;
    }

    @Override
    public void scanClass(ClassNode classNode, ScanContext context) {
        // Inspect constants recorded in context or check class details
        String classLower = classNode.name.toLowerCase(Locale.ROOT);

        if (classNode.methods != null) {
            for (MethodNode method : classNode.methods) {
                String methodLower = method.name.toLowerCase(Locale.ROOT);

                for (String hijackKey : SESSION_HIJACK_KEYWORDS) {
                    if (methodLower.contains(hijackKey) || (method.desc != null && method.desc.toLowerCase(Locale.ROOT).contains(hijackKey))) {
                        context.addFinding(Finding.builder()
                                .detectorName(getName())
                                .category(getCategory())
                                .severity(Severity.HIGH)
                                .title("Minecraft Auth/Session Manipulation")
                                .description("Method interacts with Minecraft session authentication tokens or Yggdrasil services.")
                                .className(classNode.name)
                                .methodName(method.name)
                                .methodDescriptor(method.desc)
                                .evidence("Method name/descriptor matched session keyword: " + hijackKey)
                                .remediation("Ensure session tokens are never extracted, saved, or transmitted to third parties.")
                                .build());
                    }
                }
            }
        }
    }

    @Override
    public void postScan(ScanContext context) {
        // Post-scan cross check on all string constants across the entire JAR
        for (String constant : context.getAllConstants()) {
            String lower = constant.toLowerCase(Locale.ROOT);
            for (String indicator : FRACTUREISER_INDICATORS) {
                if (lower.contains(indicator)) {
                    context.addFinding(Finding.builder()
                            .detectorName(getName())
                            .category(ThreatCategory.NETWORK_C2)
                            .severity(Severity.CRITICAL)
                            .title("Known Malware / Fractureiser Indicator Match")
                            .description("Found matching C2 host or known malware infrastructure signature: " + indicator)
                            .className("<Archive Constant Pool>")
                            .evidence("Constant string match: \"" + constant + "\"")
                            .remediation("Quarantine and delete this artifact immediately; matches known malware infrastructure.")
                            .build());
                }
            }
        }
    }
}
