package org.jarsentinel.detector;

import org.jarsentinel.detector.impl.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry and lifecycle manager for all threat detectors.
 */
public class DetectorRegistry {

    private final Map<String, Detector> registeredDetectors = new LinkedHashMap<>();
    private final Set<String> disabledDetectorIds = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public DetectorRegistry() {
        registerDefaultDetectors();
    }

    private void registerDefaultDetectors() {
        register(new TokenGrabberDetector());
        register(new ProcessExecutionDetector());
        register(new SuspiciousNetworkDetector());
        register(new DynamicClassLoadingDetector());
        register(new ReflectionAbuseDetector());
        register(new ObfuscatedStringDetector());
        register(new MinecraftPayloadDetector());
    }

    public void register(Detector detector) {
        Objects.requireNonNull(detector, "detector must not be null");
        registeredDetectors.put(detector.getId(), detector);
    }

    public void disableDetector(String id) {
        disabledDetectorIds.add(id);
    }

    public void enableDetector(String id) {
        disabledDetectorIds.remove(id);
    }

    public List<Detector> getActiveDetectors() {
        return registeredDetectors.values().stream()
                .filter(d -> !disabledDetectorIds.contains(d.getId()))
                .toList();
    }

    public Collection<Detector> getAllDetectors() {
        return Collections.unmodifiableCollection(registeredDetectors.values());
    }

    public Optional<Detector> getDetector(String id) {
        return Optional.ofNullable(registeredDetectors.get(id));
    }
}
