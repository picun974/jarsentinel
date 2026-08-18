package org.jarsentinel.core;

import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.objectweb.asm.tree.ClassNode;

import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Encapsulates the execution context of an active scan on a JAR file or directory.
 */
public class ScanContext {
    private final Path targetPath;
    private final Severity minimumSeverity;
    private final boolean deepScan;
    private final List<Finding> findings = new CopyOnWriteArrayList<>();
    private final Map<String, ClassNode> classMap = new ConcurrentHashMap<>();
    private final Set<String> allConstants = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Map<String, Object> customAttributes = new ConcurrentHashMap<>();

    public ScanContext(Path targetPath, Severity minimumSeverity, boolean deepScan) {
        this.targetPath = Objects.requireNonNull(targetPath);
        this.minimumSeverity = minimumSeverity != null ? minimumSeverity : Severity.INFO;
        this.deepScan = deepScan;
    }

    public Path getTargetPath() {
        return targetPath;
    }

    public Severity getMinimumSeverity() {
        return minimumSeverity;
    }

    public boolean isDeepScan() {
        return deepScan;
    }

    public void addFinding(Finding finding) {
        if (finding != null && finding.severity().isAtLeast(minimumSeverity)) {
            findings.add(finding);
        }
    }

    public List<Finding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    public void addClass(ClassNode classNode) {
        classMap.put(classNode.name, classNode);
    }

    public Map<String, ClassNode> getClassMap() {
        return Collections.unmodifiableMap(classMap);
    }

    public void addConstant(String constant) {
        if (constant != null && !constant.isBlank()) {
            allConstants.add(constant);
        }
    }

    public Set<String> getAllConstants() {
        return Collections.unmodifiableSet(allConstants);
    }

    public void setAttribute(String key, Object value) {
        customAttributes.put(key, value);
    }

    public Object getAttribute(String key) {
        return customAttributes.get(key);
    }
}
