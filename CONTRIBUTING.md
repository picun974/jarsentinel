# Contributing to JarSentinel

Thank you for your interest in improving **JarSentinel**! We welcome contributions from security researchers, JVM engineers, and open-source contributors.

---

## 🛠️ How to Get Started

### 1. Prerequisites
- **JDK 17** or higher
- **Maven 3.8+** or **Gradle 8.0+**
- **Git**

### 2. Fork and Clone
```bash
git clone https://github.com/picun974/jarsentinel.git
cd jarsentinel
```

### 3. Build & Test Locally
```bash
# Build and execute all test suites
mvn clean verify

# Run packaged executable on a target jar
java -jar target/jarsentinel.jar <path-to-jar>
```

---

## 🛡️ Adding a Custom Threat Detector

JarSentinel uses a modular SPI detector system. To create a new threat detector:

1. Create a class implementing `org.jarsentinel.detector.Detector`:
```java
package org.jarsentinel.detector.impl;

import org.jarsentinel.core.ScanContext;
import org.jarsentinel.detector.Detector;
import org.jarsentinel.model.*;
import org.objectweb.asm.tree.ClassNode;

public class CustomDetector implements Detector {
    @Override
    public String getId() { return "my-custom-rule"; }

    @Override
    public String getName() { return "Custom Malicious Pattern Detector"; }

    @Override
    public String getDescription() { return "Identifies custom malicious payloads."; }

    @Override
    public ThreatCategory getCategory() { return ThreatCategory.GENERAL_SUSPICIOUS; }

    @Override
    public void scanClass(ClassNode classNode, ScanContext context) {
        // Inspect ASM ClassNode bytecode instructions & constants
    }
}
```
2. Register your detector in `DetectorRegistry.java`.
3. Add comprehensive JUnit tests in `JarScannerTest.java`.

---

## 📜 Pull Request Guidelines

- Ensure `mvn test` passes cleanly with zero errors.
- Include unit test coverage for any new detector or rule logic.
- Adhere to clean Java formatting and descriptive commit messages.
