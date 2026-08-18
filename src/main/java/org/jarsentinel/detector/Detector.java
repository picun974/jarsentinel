package org.jarsentinel.detector;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.model.ThreatCategory;
import org.objectweb.asm.tree.ClassNode;

/**
 * Common SPI / Interface for static bytecode threat detectors.
 */
public interface Detector {
    /**
     * Unique identifier for this detector (e.g. "token-grabber", "process-exec").
     */
    String getId();

    /**
     * Human-readable name of the detector.
     */
    String getName();

    /**
     * Detailed description of threats this detector identifies.
     */
    String getDescription();

    /**
     * Primary threat category targeted by this detector.
     */
    ThreatCategory getCategory();

    /**
     * Analyzes an ASM ClassNode loaded from the target JAR.
     *
     * @param classNode the parsed bytecode representation of a class
     * @param context   the active scanning context to append findings
     */
    void scanClass(ClassNode classNode, ScanContext context);

    /**
     * Optional hook invoked after all classes in the target have been scanned.
     * Useful for cross-class aggregation or graph analysis.
     *
     * @param context the active scanning context
     */
    default void postScan(ScanContext context) {
        // Default no-op
    }
}
