package org.jarsentinel.model;

/**
 * High-level security verdict for a scanned archive.
 */
public enum Verdict {
    CLEAN("CLEAN / SAFE", "\u001B[32m", "✅", "No suspicious or malicious patterns identified."),
    LOW_RISK("LOW RISK", "\u001B[36m", "ℹ️", "Minor usage of internal APIs or raw networking; likely safe."),
    SUSPICIOUS("SUSPICIOUS / OBFUSCATED", "\u001B[33m", "⚠️", "Contains hidden bytecode, dynamic injection, or unusual reflection requiring review."),
    MALICIOUS("MALICIOUS / HIGH RISK", "\u001B[31m", "🚨", "Confirmed presence of credential stealers, C2 exfiltration webhooks, or dangerous payloads!");

    private final String label;
    private final String ansiColor;
    private final String icon;
    private final String summary;

    Verdict(String label, String ansiColor, String icon, String summary) {
        this.label = label;
        this.ansiColor = ansiColor;
        this.icon = icon;
        this.summary = summary;
    }

    public String getLabel() {
        return label;
    }

    public String getAnsiColor() {
        return ansiColor;
    }

    public String getIcon() {
        return icon;
    }

    public String getSummary() {
        return summary;
    }
}
