package org.jarsentinel.cli;

import org.jarsentinel.model.Severity;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Robust zero-dependency command line argument parser.
 */
public class CliArgs {
    private Path targetPath;
    private Severity minimumSeverity = Severity.LOW;
    private Severity failOnSeverity = Severity.HIGH;
    private OutputFormat format = OutputFormat.CONSOLE;
    private Path outputFile;
    private boolean noColor = false;
    private boolean showHelp = false;
    private boolean showVersion = false;
    private final List<String> disabledDetectors = new ArrayList<>();

    public enum OutputFormat {
        CONSOLE, JSON, MARKDOWN
    }

    public static CliArgs parse(String[] args) {
        CliArgs parsed = new CliArgs();

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            switch (arg) {
                case "-h", "--help" -> parsed.showHelp = true;
                case "-v", "--version" -> parsed.showVersion = true;
                case "--no-color" -> parsed.noColor = true;
                case "-p", "--path" -> {
                    if (i + 1 < args.length) {
                        parsed.targetPath = Paths.get(args[++i]);
                    }
                }
                case "-s", "--severity" -> {
                    if (i + 1 < args.length) {
                        parsed.minimumSeverity = Severity.fromString(args[++i]);
                    }
                }
                case "--fail-on" -> {
                    if (i + 1 < args.length) {
                        parsed.failOnSeverity = Severity.fromString(args[++i]);
                    }
                }
                case "-f", "--format" -> {
                    if (i + 1 < args.length) {
                        String fmt = args[++i].toUpperCase();
                        try {
                            parsed.format = OutputFormat.valueOf(fmt);
                        } catch (IllegalArgumentException e) {
                            parsed.format = OutputFormat.CONSOLE;
                        }
                    }
                }
                case "-o", "--output" -> {
                    if (i + 1 < args.length) {
                        parsed.outputFile = Paths.get(args[++i]);
                    }
                }
                case "--disable" -> {
                    if (i + 1 < args.length) {
                        parsed.disabledDetectors.add(args[++i]);
                    }
                }
                default -> {
                    if (parsed.targetPath == null && !arg.startsWith("-")) {
                        parsed.targetPath = Paths.get(arg);
                    }
                }
            }
        }

        return parsed;
    }

    public Path getTargetPath() {
        return targetPath;
    }

    public Severity getMinimumSeverity() {
        return minimumSeverity;
    }

    public Severity getFailOnSeverity() {
        return failOnSeverity;
    }

    public OutputFormat getFormat() {
        return format;
    }

    public Path getOutputFile() {
        return outputFile;
    }

    public boolean isNoColor() {
        return noColor;
    }

    public boolean isShowHelp() {
        return showHelp;
    }

    public boolean isShowVersion() {
        return showVersion;
    }

    public List<String> getDisabledDetectors() {
        return disabledDetectors;
    }
}
