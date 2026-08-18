package org.jarsentinel.core;

import org.jarsentinel.detector.Detector;
import org.jarsentinel.detector.DetectorRegistry;
import org.jarsentinel.model.Severity;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.stream.Stream;

/**
 * Core engine responsible for unpacking, reading bytecode, and executing threat detectors.
 */
public class JarScanner {

    private final DetectorRegistry registry;
    private final Severity minimumSeverity;
    private final boolean deepScan;

    public JarScanner(DetectorRegistry registry, Severity minimumSeverity, boolean deepScan) {
        this.registry = Objects.requireNonNull(registry);
        this.minimumSeverity = minimumSeverity != null ? minimumSeverity : Severity.INFO;
        this.deepScan = deepScan;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Scans a target path (a single JAR/class file or a directory recursively).
     */
    public List<ScanResult> scan(Path targetPath) {
        if (!Files.exists(targetPath)) {
            return List.of(ScanResult.failure(targetPath, 0, "Target path does not exist: " + targetPath));
        }

        List<ScanResult> results = new ArrayList<>();

        if (Files.isDirectory(targetPath)) {
            try (Stream<Path> stream = Files.walk(targetPath)) {
                List<Path> jarFiles = stream
                        .filter(p -> Files.isRegularFile(p) && (p.toString().endsWith(".jar") || p.toString().endsWith(".zip")))
                        .toList();

                for (Path jar : jarFiles) {
                    results.add(scanSingleJar(jar));
                }
            } catch (IOException e) {
                results.add(ScanResult.failure(targetPath, 0, "Failed to traverse directory: " + e.getMessage()));
            }
        } else {
            results.add(scanSingleJar(targetPath));
        }

        return results;
    }

    public ScanResult scanSingleJar(Path jarPath) {
        long startTime = System.currentTimeMillis();
        ScanContext context = new ScanContext(jarPath, minimumSeverity, deepScan);
        int classCount = 0;

        try (InputStream fis = Files.newInputStream(jarPath);
             JarInputStream jis = new JarInputStream(fis)) {

            JarEntry entry;
            List<Detector> activeDetectors = registry.getActiveDetectors();

            while ((entry = jis.getNextJarEntry()) != null) {
                if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                    if (entry.getName().startsWith("org/jarsentinel/")) {
                        jis.closeEntry();
                        continue;
                    }
                    classCount++;
                    byte[] classBytes = readAllBytes(jis);

                    try {
                        ClassReader reader = new ClassReader(classBytes);
                        ClassNode classNode = new ClassNode();
                        reader.accept(classNode, ClassReader.EXPAND_FRAMES);

                        context.addClass(classNode);

                        for (Detector detector : activeDetectors) {
                            try {
                                detector.scanClass(classNode, context);
                            } catch (Exception e) {
                                // Prevent single faulty detector from stopping entire scan
                                System.err.printf("[WARN] Detector %s failed on class %s: %s%n",
                                        detector.getId(), classNode.name, e.getMessage());
                            }
                        }
                    } catch (Exception e) {
                        System.err.printf("[WARN] Failed to parse bytecode for %s: %s%n", entry.getName(), e.getMessage());
                    }
                }
                jis.closeEntry();
            }

            // Post-scan cross analysis
            for (Detector detector : activeDetectors) {
                detector.postScan(context);
            }

            long duration = System.currentTimeMillis() - startTime;
            return ScanResult.create(jarPath, classCount, duration, context.getFindings());

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            return ScanResult.failure(jarPath, duration, "Failed to read JAR: " + e.getMessage());
        }
    }

    private byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int nRead;
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    public static class Builder {
        private DetectorRegistry registry = new DetectorRegistry();
        private Severity minimumSeverity = Severity.LOW;
        private boolean deepScan = true;

        public Builder registry(DetectorRegistry registry) {
            this.registry = registry;
            return this;
        }

        public Builder minimumSeverity(Severity minimumSeverity) {
            this.minimumSeverity = minimumSeverity;
            return this;
        }

        public Builder deepScan(boolean deepScan) {
            this.deepScan = deepScan;
            return this;
        }

        public JarScanner build() {
            return new JarScanner(registry, minimumSeverity, deepScan);
        }
    }
}
