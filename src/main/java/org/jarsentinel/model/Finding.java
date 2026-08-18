package org.jarsentinel.model;

import java.util.Objects;

/**
 * A detected security finding within a scanned class or bytecode artifact.
 */
public record Finding(
        String detectorName,
        ThreatCategory category,
        Severity severity,
        String title,
        String description,
        String className,
        String methodName,
        String methodDescriptor,
        int lineNumber,
        String evidence,
        String remediation
) {
    public Finding {
        Objects.requireNonNull(detectorName, "detectorName must not be null");
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(title, "title must not be null");
        Objects.requireNonNull(className, "className must not be null");
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String detectorName = "Unknown";
        private ThreatCategory category = ThreatCategory.GENERAL_SUSPICIOUS;
        private Severity severity = Severity.MEDIUM;
        private String title = "";
        private String description = "";
        private String className = "";
        private String methodName = "";
        private String methodDescriptor = "";
        private int lineNumber = -1;
        private String evidence = "";
        private String remediation = "";

        public Builder detectorName(String detectorName) {
            this.detectorName = detectorName;
            return this;
        }

        public Builder category(ThreatCategory category) {
            this.category = category;
            return this;
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder className(String className) {
            this.className = className;
            return this;
        }

        public Builder methodName(String methodName) {
            this.methodName = methodName;
            return this;
        }

        public Builder methodDescriptor(String methodDescriptor) {
            this.methodDescriptor = methodDescriptor;
            return this;
        }

        public Builder lineNumber(int lineNumber) {
            this.lineNumber = lineNumber;
            return this;
        }

        public Builder evidence(String evidence) {
            this.evidence = evidence;
            return this;
        }

        public Builder remediation(String remediation) {
            this.remediation = remediation;
            return this;
        }

        public Finding build() {
            return new Finding(
                    detectorName,
                    category,
                    severity,
                    title,
                    description,
                    className,
                    methodName,
                    methodDescriptor,
                    lineNumber,
                    evidence,
                    remediation
            );
        }
    }
}
