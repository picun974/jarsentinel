package org.jarsentinel.model;

/**
 * Categorization of threats detected by bytecode inspection.
 */
public enum ThreatCategory {
    CREDENTIAL_STEALER("Credential / Token Stealer", "Attempts to access Discord, browser, or crypto credentials"),
    PROCESS_EXECUTION("Process / Shell Execution", "Executes system commands, powershell, or shell scripts"),
    NETWORK_C2("Suspicious Network / C2", "Hardcoded Webhooks, raw socket connections, or remote payload fetches"),
    DYNAMIC_INJECTION("Dynamic Class Injection", "Runtime bytecode injection, custom ClassLoaders, or agent attachment"),
    REFLECTION_ABUSE("Reflection / Unsafe Abuse", "Accesses Unsafe internals, private field access, or sandbox escapes"),
    OBFUSCATION_MALICIOUS("Malicious Obfuscation", "Bytecode encryption, XOR loops, or anti-analysis payload concealment"),
    PERSISTENCE("Persistence & Auto-Start", "Attempts to establish startup persistence in the host operating system"),
    GENERAL_SUSPICIOUS("Suspicious Pattern", "Anomalous bytecode construct requiring manual review");

    private final String displayName;
    private final String description;

    ThreatCategory(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
