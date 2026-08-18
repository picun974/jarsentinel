package org.jarsentinel.report;

import org.jarsentinel.core.ScanResult;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.model.Verdict;

import java.io.PrintStream;
import java.util.List;

/**
 * Pretty-prints scanning results to the standard console with ANSI formatting, verdict blocks, and highlights.
 */
public class ConsoleReporter {

    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String DIM = "\u001B[2m";
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String RED = "\u001B[31m";
    private static final String WHITE_BG_RED = "\u001B[41m\u001B[37m";
    private static final String WHITE_BG_YELLOW = "\u001B[43m\u001B[30m";
    private static final String WHITE_BG_GREEN = "\u001B[42m\u001B[30m";

    private final PrintStream out;
    private final boolean ansiEnabled;

    public ConsoleReporter(PrintStream out, boolean ansiEnabled) {
        this.out = out;
        this.ansiEnabled = ansiEnabled;
    }

    public ConsoleReporter() {
        this(System.out, true);
    }

    public void report(List<ScanResult> results) {
        for (ScanResult result : results) {
            reportSingle(result);
        }
        reportAggregatedSummary(results);
    }

    public void reportSingle(ScanResult result) {
        out.println();
        out.println(repeat("-", 80));
        out.println(color(BOLD + "Target: " + RESET, "") + result.targetPath());
        out.println(color(DIM + "Classes scanned: " + result.totalClassesScanned() + " | Time: " + result.scanDurationMillis() + "ms" + RESET, ""));

        // Render Top Verdict Box
        printVerdictBanner(result);

        if (result.findings().isEmpty()) {
            return;
        }

        out.println(color(BOLD + "DETAILED FINDINGS (" + result.findings().size() + "):" + RESET, "DETAILED FINDINGS:"));
        int index = 1;
        for (Finding finding : result.findings()) {
            String badge = getSeverityBadge(finding.severity());
            out.printf(" %2d. %s %s%s%s%n", index++, badge, color(BOLD, ""), finding.title(), color(RESET, ""));
            out.printf("     %sCategory:%s %s | %sDetector:%s %s%n",
                    color(DIM, ""), color(RESET, ""), finding.category().getDisplayName(),
                    color(DIM, ""), color(RESET, ""), finding.detectorName());
            out.printf("     %sLocation:%s %s%s%s%n",
                    color(DIM, ""), color(RESET, ""),
                    finding.className(),
                    finding.methodName().isEmpty() ? "" : "#" + finding.methodName() + (finding.lineNumber() > 0 ? ":" + finding.lineNumber() : ""),
                    finding.methodDescriptor().isEmpty() ? "" : " " + finding.methodDescriptor());

            if (!finding.evidence().isEmpty()) {
                out.printf("     %sEvidence:%s %s%n", color(YELLOW, ""), color(RESET, ""), finding.evidence());
            }
            if (!finding.description().isEmpty()) {
                out.printf("     %sDetails:%s  %s%n", color(DIM, ""), color(RESET, ""), finding.description());
            }
            if (!finding.remediation().isEmpty()) {
                out.printf("     %sFix:%s      %s%n", color(CYAN, ""), color(RESET, ""), finding.remediation());
            }
            out.println();
        }
    }

    private void printVerdictBanner(ScanResult result) {
        Verdict verdict = result.verdict();
        String verdictColor = verdict.getAnsiColor();

        out.println();
        out.println(color(BOLD + "ИТОГ / ВЕРДИКТ: " + verdictColor + verdict.getIcon() + " " + verdict.getLabel() + RESET,
                "ИТОГ / ВЕРДИКТ: [" + verdict.getLabel() + "]"));
        out.println(color(DIM + "» " + verdict.getSummary() + RESET, "» " + verdict.getSummary()));

        if (!result.highlights().isEmpty()) {
            out.println();
            out.println(color(BOLD + "📌 КРАТКАЯ СВОДКА (ЧТО НАЙДЕНО В ФАЙЛЕ):" + RESET, "📌 КРАТКАЯ СВОДКА (ЧТО НАЙДЕНО):"));
            for (String highlight : result.highlights()) {
                out.println("   " + highlight);
            }
        }
        out.println();
    }

    private void reportAggregatedSummary(List<ScanResult> results) {
        int totalScanned = results.stream().mapToInt(ScanResult::totalClassesScanned).sum();
        int totalFindings = results.stream().mapToInt(r -> r.findings().size()).sum();
        long criticalCount = results.stream().mapToLong(r -> r.getCount(Severity.CRITICAL)).sum();
        long highCount = results.stream().mapToLong(r -> r.getCount(Severity.HIGH)).sum();
        long mediumCount = results.stream().mapToLong(r -> r.getCount(Severity.MEDIUM)).sum();
        long lowCount = results.stream().mapToLong(r -> r.getCount(Severity.LOW)).sum();

        out.println(repeat("=", 80));
        out.println(color(BOLD + "ALL TARGETS SCAN SUMMARY" + RESET, "ALL TARGETS SCAN SUMMARY"));
        out.printf(" Total Targets: %d | Total Classes: %d | Total Findings: %d%n", results.size(), totalScanned, totalFindings);
        out.printf(" %sCRITICAL: %d%s | %sHIGH: %d%s | %sMEDIUM: %d%s | %sLOW: %d%s%n",
                color(RED + BOLD, ""), criticalCount, color(RESET, ""),
                color(RED, ""), highCount, color(RESET, ""),
                color(YELLOW, ""), mediumCount, color(RESET, ""),
                color(GREEN, ""), lowCount, color(RESET, ""));
        out.println(repeat("=", 80));
    }

    private String getSeverityBadge(Severity severity) {
        if (!ansiEnabled) {
            return "[" + severity.getLabel() + "]";
        }
        return switch (severity) {
            case CRITICAL -> WHITE_BG_RED + " CRITICAL " + RESET;
            case HIGH -> RED + BOLD + "[HIGH]" + RESET;
            case MEDIUM -> YELLOW + "[MEDIUM]" + RESET;
            case LOW -> GREEN + "[LOW]" + RESET;
            case INFO -> CYAN + "[INFO]" + RESET;
        };
    }

    private String color(String ansi, String fallback) {
        return ansiEnabled ? ansi : fallback;
    }

    private String repeat(String s, int times) {
        return s.repeat(Math.max(0, times));
    }
}
