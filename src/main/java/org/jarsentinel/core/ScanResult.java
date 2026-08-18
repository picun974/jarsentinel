package org.jarsentinel.core;

import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.ThreatCategory;
import org.jarsentinel.model.Verdict;

import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Immutable representation of completed scan results with overall Verdict and Highlights.
 */
public record ScanResult(
        Path targetPath,
        int totalClassesScanned,
        long scanDurationMillis,
        List<Finding> findings,
        Map<Severity, Long> severityCounts,
        Verdict verdict,
        List<String> highlights,
        boolean success
) {
    public ScanResult {
        findings = List.copyOf(findings);
        severityCounts = Map.copyOf(severityCounts);
        highlights = List.copyOf(highlights);
    }

    public static ScanResult create(Path path, int classesScanned, long durationMillis, List<Finding> findings) {
        Map<Severity, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(Finding::severity, Collectors.counting()));

        for (Severity s : Severity.values()) {
            counts.putIfAbsent(s, 0L);
        }

        Verdict computedVerdict = computeVerdict(counts, findings);
        List<String> computedHighlights = generateHighlights(findings);

        return new ScanResult(
                path,
                classesScanned,
                durationMillis,
                findings,
                counts,
                computedVerdict,
                computedHighlights,
                true
        );
    }

    public static ScanResult failure(Path path, long durationMillis, String errorMessage) {
        Finding errorFinding = Finding.builder()
                .detectorName("ScannerEngine")
                .severity(Severity.CRITICAL)
                .title("Scan Failure")
                .description(errorMessage)
                .className(path.toString())
                .build();

        return new ScanResult(
                path,
                0,
                durationMillis,
                List.of(errorFinding),
                Map.of(Severity.CRITICAL, 1L),
                Verdict.MALICIOUS,
                List.of("Scan execution failed: " + errorMessage),
                false
        );
    }

    private static Verdict computeVerdict(Map<Severity, Long> counts, List<Finding> findings) {
        if (findings.isEmpty()) {
            return Verdict.CLEAN;
        }

        if (counts.getOrDefault(Severity.CRITICAL, 0L) > 0) {
            return Verdict.MALICIOUS;
        }

        long highCount = counts.getOrDefault(Severity.HIGH, 0L);
        if (highCount > 0) {
            boolean hasStealerOrInjection = findings.stream().anyMatch(f ->
                    f.category() == ThreatCategory.CREDENTIAL_STEALER ||
                    f.category() == ThreatCategory.DYNAMIC_INJECTION ||
                    f.category() == ThreatCategory.NETWORK_C2
            );
            return hasStealerOrInjection ? Verdict.MALICIOUS : Verdict.SUSPICIOUS;
        }

        if (counts.getOrDefault(Severity.MEDIUM, 0L) > 0) {
            return Verdict.SUSPICIOUS;
        }

        return Verdict.LOW_RISK;
    }

    private static List<String> generateHighlights(List<Finding> findings) {
        Set<String> items = new LinkedHashSet<>();

        for (Finding f : findings) {
            if (f.category() == ThreatCategory.CREDENTIAL_STEALER) {
                items.add("🚨 Credential Stealer: Targeted access to browser tokens, Discord sessions, or login stores");
            }
            if (f.category() == ThreatCategory.NETWORK_C2) {
                items.add("🌐 C2 Exfiltration: Hardcoded Discord Webhooks, Telegram bot tokens, or raw C2 connections");
            }
            if (f.category() == ThreatCategory.DYNAMIC_INJECTION) {
                items.add("💉 Dynamic Bytecode Dropper: Uses ClassLoader.defineClass to inject hidden code in-memory");
            }
            if (f.category() == ThreatCategory.PROCESS_EXECUTION) {
                items.add("⚙️ Native Process Spawning: Executes system commands via Runtime.exec / ProcessBuilder");
            }
            if (f.category() == ThreatCategory.OBFUSCATION_MALICIOUS) {
                items.add("🧩 Bytecode Obfuscation: Contains XOR string decryption loops & deobfuscators");
            }
            if (f.category() == ThreatCategory.REFLECTION_ABUSE) {
                items.add("🔓 Reflection / JVM Bypass: Bypasses access modifiers (setAccessible) or accesses Unsafe memory");
            }
            if (f.title().contains("HWID")) {
                items.add("🔍 Hardware Fingerprinting: Queries system serial numbers, motherboard UUIDs, or WMIC data");
            }
            if (f.title().contains("Minecraft Auth")) {
                items.add("🔑 Account Session Manager: Interacts with Minecraft authentication and token sessions");
            }
        }

        if (items.isEmpty() && !findings.isEmpty()) {
            items.add("ℹ️ Minor low-level API usage detected requiring routine review");
        }

        return new ArrayList<>(items);
    }

    public boolean hasCriticalFindings() {
        return severityCounts.getOrDefault(Severity.CRITICAL, 0L) > 0;
    }

    public long getCount(Severity severity) {
        return severityCounts.getOrDefault(severity, 0L);
    }
}
