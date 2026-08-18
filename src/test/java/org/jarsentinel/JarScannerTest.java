package org.jarsentinel;

import org.jarsentinel.core.JarScanner;
import org.jarsentinel.core.ScanContext;
import org.jarsentinel.core.ScanResult;
import org.jarsentinel.detector.DetectorRegistry;
import org.jarsentinel.detector.impl.*;
import org.jarsentinel.model.Finding;
import org.jarsentinel.model.Severity;
import org.jarsentinel.report.JsonReporter;
import org.jarsentinel.report.MarkdownReporter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

public class JarScannerTest implements Opcodes {

    private DetectorRegistry registry;

    @BeforeEach
    public void setup() {
        registry = new DetectorRegistry();
    }

    @Test
    public void testCleanClassYieldsNoFindings() {
        ClassNode cleanClass = createCleanClassNode();
        ScanContext context = new ScanContext(Path.of("test.jar"), Severity.INFO, true);

        for (var detector : registry.getActiveDetectors()) {
            detector.scanClass(cleanClass, context);
        }

        assertTrue(context.getFindings().isEmpty(), "Clean class should produce no security findings");
    }

    @Test
    public void testTokenGrabberDetection() {
        ClassNode stealerNode = createStealerClassNode();
        ScanContext context = new ScanContext(Path.of("stealer.jar"), Severity.INFO, true);

        TokenGrabberDetector detector = new TokenGrabberDetector();
        detector.scanClass(stealerNode, context);

        assertFalse(context.getFindings().isEmpty(), "Stealer path should trigger finding");
        assertTrue(context.getFindings().stream().anyMatch(f -> f.severity() == Severity.CRITICAL));
    }

    @Test
    public void testProcessExecutionDetection() {
        ClassNode execNode = createProcessExecClassNode();
        ScanContext context = new ScanContext(Path.of("malware.jar"), Severity.INFO, true);

        ProcessExecutionDetector detector = new ProcessExecutionDetector();
        detector.scanClass(execNode, context);

        assertFalse(context.getFindings().isEmpty(), "Process execution should trigger finding");
        assertTrue(context.getFindings().stream().anyMatch(f -> f.severity() == Severity.CRITICAL));
    }

    @Test
    public void testSuspiciousWebhookDetection() {
        ClassNode webhookNode = createWebhookClassNode();
        ScanContext context = new ScanContext(Path.of("logger.jar"), Severity.INFO, true);

        SuspiciousNetworkDetector detector = new SuspiciousNetworkDetector();
        detector.scanClass(webhookNode, context);

        assertFalse(context.getFindings().isEmpty(), "Discord webhook should trigger finding");
        assertTrue(context.getFindings().stream().anyMatch(f -> f.title().contains("Discord Webhook")));
    }

    @Test
    public void testXorDecryptionLoopDetection() {
        ClassNode xorNode = createXorDecryptorClassNode();
        ScanContext context = new ScanContext(Path.of("obf.jar"), Severity.INFO, true);

        ObfuscatedStringDetector detector = new ObfuscatedStringDetector();
        detector.scanClass(xorNode, context);

        assertFalse(context.getFindings().isEmpty(), "XOR loop should trigger deobfuscator finding");
    }

    @Test
    public void testJarScannerEndToEnd() throws Exception {
        Path tempJar = Files.createTempFile("test-scan", ".jar");
        tempJar.toFile().deleteOnExit();

        byte[] classBytes = createSyntheticClassBytes();

        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(tempJar.toFile()))) {
            jos.putNextEntry(new JarEntry("com/example/Payload.class"));
            jos.write(classBytes);
            jos.closeEntry();
        }

        JarScanner scanner = JarScanner.builder()
                .registry(registry)
                .minimumSeverity(Severity.LOW)
                .build();

        List<ScanResult> results = scanner.scan(tempJar);

        assertEquals(1, results.size());
        ScanResult result = results.get(0);
        assertEquals(1, result.totalClassesScanned());
        assertFalse(result.findings().isEmpty());

        // Test JSON & Markdown reporting
        JsonReporter jsonReporter = new JsonReporter();
        String json = jsonReporter.toJson(results);
        assertTrue(json.contains("\"critical\":"));

        MarkdownReporter mdReporter = new MarkdownReporter();
        String md = mdReporter.toMarkdown(results);
        assertTrue(md.contains("JarSentinel Security Analysis Report"));
    }

    private ClassNode createCleanClassNode() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V17, ACC_PUBLIC, "com/example/CleanService", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "greet", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitLdcInsn("Hello, ");
        mv.visitInsn(ARETURN);
        mv.visitMaxs(1, 2);
        mv.visitEnd();
        cw.visitEnd();

        return toClassNode(cw.toByteArray());
    }

    private ClassNode createStealerClassNode() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V17, ACC_PUBLIC, "com/example/Stealer", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "steal", "()V", null, null);
        mv.visitCode();
        mv.visitLdcInsn("AppData/Roaming/discord/Local Storage/leveldb");
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        cw.visitEnd();

        return toClassNode(cw.toByteArray());
    }

    private ClassNode createProcessExecClassNode() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V17, ACC_PUBLIC, "com/example/Dropper", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "drop", "()V", null, null);
        mv.visitCode();
        mv.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        mv.visitLdcInsn("powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA");
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();
        cw.visitEnd();

        return toClassNode(cw.toByteArray());
    }

    private ClassNode createWebhookClassNode() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V17, ACC_PUBLIC, "com/example/Exfil", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "send", "()V", null, null);
        mv.visitCode();
        mv.visitLdcInsn("https://discord.com/api/webhooks/1234567890/tokenABCDEF123456");
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        cw.visitEnd();

        return toClassNode(cw.toByteArray());
    }

    private ClassNode createXorDecryptorClassNode() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V17, ACC_PUBLIC, "com/example/Decryptor", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "decrypt", "([BI)[B", null, null);
        mv.visitCode();
        Label loopStart = new Label();
        Label loopEnd = new Label();

        mv.visitInsn(ICONST_0);
        mv.visitVarInsn(ISTORE, 2); // i = 0

        mv.visitLabel(loopStart);
        mv.visitVarInsn(ILOAD, 2);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitInsn(ARRAYLENGTH);
        mv.visitJumpInsn(IF_ICMPGE, loopEnd);

        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ILOAD, 2);
        mv.visitInsn(DUP2);
        mv.visitInsn(BALOAD);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(IXOR); // IXOR operation
        mv.visitInsn(BASTORE); // BASTORE

        mv.visitIincInsn(2, 1);
        mv.visitJumpInsn(GOTO, loopStart); // loop backward

        mv.visitLabel(loopEnd);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitInsn(ARETURN);
        mv.visitMaxs(4, 3);
        mv.visitEnd();
        cw.visitEnd();

        return toClassNode(cw.toByteArray());
    }

    private byte[] createSyntheticClassBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V17, ACC_PUBLIC, "com/example/Payload", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "run", "()V", null, null);
        mv.visitCode();
        mv.visitLdcInsn("https://discord.com/api/webhooks/9999999/secretWebhookToken");
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        cw.visitEnd();

        return cw.toByteArray();
    }

    private ClassNode toClassNode(byte[] bytes) {
        org.objectweb.asm.ClassReader cr = new org.objectweb.asm.ClassReader(bytes);
        ClassNode cn = new ClassNode();
        cr.accept(cn, 0);
        return cn;
    }
}
