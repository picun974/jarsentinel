package org.jarsentinel.core;

import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Immutable representation of completed scan results.
 */
public record ScanResult(
        Path targetPath,
        int totalClassesScanned,
        long scanDurationMillis,
        List<Finding> findings,
        Map<Severity, Long> severityCounts,
        boolean success
) {
    public ScanResult {
        findings = List.copyOf(findings);
        severityCounts = Map.copyOf(severityCounts);
    }

    public static ScanResult create(Path path, int classesScanned, long durationMillis, List<Finding> findings) {
        Map<Severity, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(Finding::severity, Collectors.counting()));

        // Ensure all severities exist in map with 0 default
        for (Severity s : Severity.values()) {
            counts.putIfAbsent(s, 0L);
        }

        return new ScanResult(
                path,
                classesScanned,
                durationMillis,
                findings,
                counts,
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
                false
        );
    }

    public boolean hasCriticalFindings() {
        return severityCounts.getOrDefault(Severity.CRITICAL, 0L) > 0;
    }

    public boolean hasHighOrCriticalFindings() {
        return severityCounts.getOrDefault(Severity.CRITICAL, 0L) > 0
                || severityCounts.getOrDefault(Severity.HIGH, 0L) > 0;
    }

    public long getCount(Severity severity) {
        return severityCounts.getOrDefault(severity, 0L);
    }
}
