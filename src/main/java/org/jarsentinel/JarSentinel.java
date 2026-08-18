package org.jarsentinel;

import org.jarsentinel.cli.CliArgs;
import org.jarsentinel.core.JarScanner;
import org.jarsentinel.core.ScanResult;
import org.jarsentinel.detector.DetectorRegistry;
import org.jarsentinel.model.Finding;
import org.jarsentinel.report.ConsoleReporter;
import org.jarsentinel.report.JsonReporter;
import org.jarsentinel.report.MarkdownReporter;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * Main application entrypoint for JarSentinel CLI.
 */
public class JarSentinel {

    public static final String VERSION = "1.0.0";

    public static void main(String[] args) {
        int exitCode = run(args);
        System.exit(exitCode);
    }

    public static int run(String[] args) {
        CliArgs parsed = CliArgs.parse(args);

        if (parsed.isShowVersion()) {
            System.out.println("JarSentinel version " + VERSION);
            return 0;
        }

        if (parsed.isShowHelp() || parsed.getTargetPath() == null) {
            printBanner();
            printUsage();
            return parsed.isShowHelp() ? 0 : 1;
        }

        if (parsed.getFormat() == CliArgs.OutputFormat.CONSOLE) {
            printBanner();
        }

        // Initialize detectors
        DetectorRegistry registry = new DetectorRegistry();
        for (String disabled : parsed.getDisabledDetectors()) {
            registry.disableDetector(disabled);
        }

        JarScanner scanner = JarScanner.builder()
                .registry(registry)
                .minimumSeverity(parsed.getMinimumSeverity())
                .deepScan(true)
                .build();

        List<ScanResult> results = scanner.scan(parsed.getTargetPath());

        // Render report
        switch (parsed.getFormat()) {
            case CONSOLE -> {
                ConsoleReporter reporter = new ConsoleReporter(System.out, !parsed.isNoColor());
                reporter.report(results);
            }
            case JSON -> {
                JsonReporter jsonReporter = new JsonReporter();
                String json = jsonReporter.toJson(results);
                outputReport(json, parsed);
            }
            case MARKDOWN -> {
                MarkdownReporter mdReporter = new MarkdownReporter();
                String md = mdReporter.toMarkdown(results);
                outputReport(md, parsed);
            }
        }

        // Evaluate exit code based on fail-on severity threshold
        boolean failBuild = results.stream().anyMatch(res ->
                res.findings().stream().anyMatch(f -> f.severity().isAtLeast(parsed.getFailOnSeverity()))
        );

        return failBuild ? 2 : 0;
    }

    private static void outputReport(String content, CliArgs args) {
        if (args.getOutputFile() != null) {
            try {
                Files.writeString(args.getOutputFile(), content, StandardCharsets.UTF_8);
                System.out.println("[+] Report successfully written to: " + args.getOutputFile());
            } catch (Exception e) {
                System.err.println("[-] Failed to write output file: " + e.getMessage());
            }
        } else {
            System.out.println(content);
        }
    }

    private static void printBanner() {
        try (InputStream is = JarSentinel.class.getResourceAsStream("/banner.txt")) {
            if (is != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("\u001B[36m" + line + "\u001B[0m");
                }
                System.out.println();
            }
        } catch (Exception ignored) {
        }
    }

    private static void printUsage() {
        System.out.println("""
            USAGE:
              java -jar jarsentinel.jar [OPTIONS] <path-to-jar-or-dir>

            OPTIONS:
              -p, --path <path>          Path to target .jar file or directory
              -s, --severity <level>     Minimum severity to report: INFO, LOW, MEDIUM, HIGH, CRITICAL (default: LOW)
              -f, --format <format>      Output format: CONSOLE, JSON, MARKDOWN (default: CONSOLE)
              -o, --output <file>        Save report to designated output file
              --fail-on <level>          Exit with code 2 if threats equal or exceed this level (default: HIGH)
              --disable <detector-id>    Disable specific detector (e.g. --disable token-grabber)
              --no-color                 Disable ANSI terminal color output
              -v, --version              Print JarSentinel version
              -h, --help                 Show this help manual

            EXAMPLES:
              java -jar jarsentinel.jar suspicious-mod.jar
              java -jar jarsentinel.jar -p ./plugins/ -f MARKDOWN -o security-report.md
              java -jar jarsentinel.jar my-app.jar --fail-on CRITICAL -f JSON
            """);
    }
}
