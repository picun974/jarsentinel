package org.jarsentinel.report;

import org.jarsentinel.core.ScanResult;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;

import java.util.List;

/**
 * Formats findings as GitHub Flavored Markdown for CI/CD reports and pull request comments.
 */
public class MarkdownReporter {

    public String toMarkdown(List<ScanResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("# 🛡️ JarSentinel Security Analysis Report\n\n");

        int totalScanned = results.stream().mapToInt(ScanResult::totalClassesScanned).sum();
        int totalFindings = results.stream().mapToInt(r -> r.findings().size()).sum();
        long criticalCount = results.stream().mapToLong(r -> r.getCount(Severity.CRITICAL)).sum();
        long highCount = results.stream().mapToLong(r -> r.getCount(Severity.HIGH)).sum();

        sb.append("### 📊 Executive Summary\n\n");
        sb.append("| Metric | Value |\n");
        sb.append("| :--- | :--- |\n");
        sb.append("| **Total Archives Scanned** | ").append(results.size()).append(" |\n");
        sb.append("| **Total Classes Parsed** | ").append(totalScanned).append(" |\n");
        sb.append("| **Total Threats Detected** | ").append(totalFindings).append(" |\n");
        sb.append("| **Critical Findings** | 🚨 **").append(criticalCount).append("** |\n");
        sb.append("| **High Severity Findings** | ⚠️ **").append(highCount).append("** |\n\n");

        for (ScanResult r : results) {
            sb.append("## 📦 Target: `").append(r.targetPath().getFileName()).append("`\n\n");
            sb.append("- **Location**: `").append(r.targetPath()).append("`\n");
            sb.append("- **Classes Scanned**: ").append(r.totalClassesScanned()).append("\n");
            sb.append("- **Scan Duration**: ").append(r.scanDurationMillis()).append(" ms\n\n");

            if (r.findings().isEmpty()) {
                sb.append("> ✅ **Clean:** No security threats or suspicious bytecode patterns identified.\n\n");
                continue;
            }

            sb.append("| Severity | Title | Category | Location | Evidence |\n");
            sb.append("| :--- | :--- | :--- | :--- | :--- |\n");

            for (Finding f : r.findings()) {
                String badge = switch (f.severity()) {
                    case CRITICAL -> "🚨 `CRITICAL`";
                    case HIGH -> "⚠️ `HIGH`";
                    case MEDIUM -> "🟡 `MEDIUM`";
                    case LOW -> "🟢 `LOW`";
                    case INFO -> "ℹ️ `INFO`";
                };

                String location = "`" + f.className() + (f.methodName().isEmpty() ? "" : "#" + f.methodName()) + "`";
                String evidence = f.evidence().isEmpty() ? "-" : "`" + f.evidence().replace("`", "'") + "`";

                sb.append("| ").append(badge)
                        .append(" | ").append(f.title())
                        .append(" | ").append(f.category().getDisplayName())
                        .append(" | ").append(location)
                        .append(" | ").append(evidence)
                        .append(" |\n");
            }
            sb.append("\n");
        }

        sb.append("---\n*Generated automatically by [JarSentinel](https://github.com/picun974/jarsentinel)*\n");
        return sb.toString();
    }
}
