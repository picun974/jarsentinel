package org.jarsentinel.model;

/**
 * Represents the severity level of a detected security finding.
 */
public enum Severity {
    INFO(1, "\u001B[36m", "INFO"),
    LOW(2, "\u001B[32m", "LOW"),
    MEDIUM(3, "\u001B[33m", "MEDIUM"),
    HIGH(4, "\u001B[35m", "HIGH"),
    CRITICAL(5, "\u001B[31m", "CRITICAL");

    private final int level;
    private final String ansiColor;
    private final String label;

    Severity(int level, String ansiColor, String label) {
        this.level = level;
        this.ansiColor = ansiColor;
        this.label = label;
    }

    public int getLevel() {
        return level;
    }

    public String getAnsiColor() {
        return ansiColor;
    }

    public String getLabel() {
        return label;
    }

    public boolean isAtLeast(Severity other) {
        return this.level >= other.level;
    }

    public static Severity fromString(String str) {
        if (str == null || str.isBlank()) {
            return LOW;
        }
        try {
            return Severity.valueOf(str.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return LOW;
        }
    }
}
