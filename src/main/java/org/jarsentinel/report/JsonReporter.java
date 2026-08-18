package org.jarsentinel.report;

import org.jarsentinel.core.ScanResult;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;

import java.util.List;

/**
 * Serializes scan results to JSON including Verdict and Highlights.
 */
public class JsonReporter {

    public String toJson(List<ScanResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"version\": \"1.1.0\",\n");
        sb.append("  \"results\": [\n");

        for (int i = 0; i < results.size(); i++) {
            ScanResult r = results.get(i);
            sb.append("    {\n");
            sb.append("      \"target\": \"").append(escapeJson(r.targetPath().toString())).append("\",\n");
            sb.append("      \"classesScanned\": ").append(r.totalClassesScanned()).append(",\n");
            sb.append("      \"durationMs\": ").append(r.scanDurationMillis()).append(",\n");
            sb.append("      \"verdict\": \"").append(r.verdict().name()).append("\",\n");
            sb.append("      \"verdictLabel\": \"").append(escapeJson(r.verdict().getLabel())).append("\",\n");
            sb.append("      \"success\": ").append(r.success()).append(",\n");

            // Highlights
            sb.append("      \"highlights\": [\n");
            for (int h = 0; h < r.highlights().size(); h++) {
                sb.append("        \"").append(escapeJson(r.highlights().get(h))).append("\"")
                        .append(h < r.highlights().size() - 1 ? "," : "").append("\n");
            }
            sb.append("      ],\n");

            sb.append("      \"summary\": {\n");
            sb.append("        \"critical\": ").append(r.getCount(Severity.CRITICAL)).append(",\n");
            sb.append("        \"high\": ").append(r.getCount(Severity.HIGH)).append(",\n");
            sb.append("        \"medium\": ").append(r.getCount(Severity.MEDIUM)).append(",\n");
            sb.append("        \"low\": ").append(r.getCount(Severity.LOW)).append(",\n");
            sb.append("        \"info\": ").append(r.getCount(Severity.INFO)).append("\n");
            sb.append("      },\n");
            sb.append("      \"findings\": [\n");

            for (int j = 0; j < r.findings().size(); j++) {
                Finding f = r.findings().get(j);
                sb.append("        {\n");
                sb.append("          \"title\": \"").append(escapeJson(f.title())).append("\",\n");
                sb.append("          \"severity\": \"").append(f.severity().name()).append("\",\n");
                sb.append("          \"category\": \"").append(f.category().name()).append("\",\n");
                sb.append("          \"detector\": \"").append(escapeJson(f.detectorName())).append("\",\n");
                sb.append("          \"class\": \"").append(escapeJson(f.className())).append("\",\n");
                sb.append("          \"method\": \"").append(escapeJson(f.methodName())).append("\",\n");
                sb.append("          \"line\": ").append(f.lineNumber()).append(",\n");
                sb.append("          \"evidence\": \"").append(escapeJson(f.evidence())).append("\",\n");
                sb.append("          \"description\": \"").append(escapeJson(f.description())).append("\",\n");
                sb.append("          \"remediation\": \"").append(escapeJson(f.remediation())).append("\"\n");
                sb.append("        }").append(j < r.findings().size() - 1 ? "," : "").append("\n");
            }

            sb.append("      ]\n");
            sb.append("    }").append(i < results.size() - 1 ? "," : "").append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
