package io.mosip.testrig.conformance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Launches the harness ({@code python -m icg run}) as a subprocess and loads its results.
 *
 * <p>Results are cached per component for the lifetime of the JVM: the TestNG data provider
 * and the test methods of one suite share a single conformance run.
 */
public final class ConformanceRunner {

    private static final Logger LOG = Logger.getLogger(ConformanceRunner.class.getName());
    private static final ConcurrentHashMap<String, ConformanceResults> CACHE = new ConcurrentHashMap<>();

    /** Harness exit codes: 0 gate passed, 1 gate failed, anything else = infrastructure error. */
    public static final int EXIT_GATE_FAILED = 1;

    private ConformanceRunner() {
    }

    public static ConformanceResults runOrLoad(ConformanceRunConfig config) throws ConformanceException {
        try {
            return CACHE.computeIfAbsent(config.component(), c -> {
                try {
                    return execute(config);
                } catch (ConformanceException e) {
                    throw new IllegalStateException(e);
                }
            });
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof ConformanceException ce) {
                throw ce;
            }
            throw e;
        }
    }

    static ConformanceResults execute(ConformanceRunConfig config) throws ConformanceException {
        if (config.existingResults() != null) {
            LOG.info("Loading existing conformance results from " + config.existingResults());
            return read(config.existingResults());
        }
        Path harnessDir = config.harnessHome().resolve("harness");
        if (!Files.isDirectory(harnessDir.resolve("icg"))) {
            throw new ConformanceException("Harness not found at " + harnessDir
                    + " (set " + ConformanceRunConfig.KEY_HARNESS_HOME + ")");
        }
        Path outDir = config.outputDir().resolve(config.component());
        Path logFile = outDir.resolve("harness-" + config.component() + ".log");
        try {
            Files.createDirectories(outDir);
        } catch (IOException e) {
            throw new ConformanceException("Cannot create " + outDir, e);
        }

        List<String> command = new ArrayList<>(List.of(
                config.python(), "-m", "icg", "run",
                "--component", config.component(),
                "--out", outDir.toString()));
        if (!config.seedCertify()) {
            command.add("--no-seed");
        }
        ProcessBuilder builder = new ProcessBuilder(command)
                .directory(harnessDir.toFile())
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile.toFile()));
        builder.environment().putAll(config.harnessEnvironment());
        builder.environment().merge("PYTHONPATH", harnessDir.toString(),
                (existing, added) -> added + java.io.File.pathSeparator + existing);

        LOG.info("Starting conformance harness: " + String.join(" ", command) + " (log: " + logFile + ")");
        int exit;
        try {
            Process process = builder.start();
            if (!process.waitFor(config.timeout().toMinutes(), TimeUnit.MINUTES)) {
                process.destroyForcibly();
                throw new ConformanceException("Conformance harness exceeded " + config.timeout() + "; see " + logFile);
            }
            exit = process.exitValue();
        } catch (IOException e) {
            throw new ConformanceException("Could not start '" + config.python() + "': " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConformanceException("Interrupted while waiting for the conformance harness", e);
        }

        Path results = outDir.resolve("latest-results.json");
        if (exit != 0 && exit != EXIT_GATE_FAILED) {
            throw new ConformanceException("Conformance harness infrastructure error (exit " + exit + "); see " + logFile);
        }
        return read(results);
    }

    private static ConformanceResults read(Path file) throws ConformanceException {
        try {
            return ConformanceResults.read(file);
        } catch (IOException e) {
            throw new ConformanceException("Cannot read conformance results " + file + ": " + e.getMessage(), e);
        }
    }

    /** Visible for tests. */
    static void clearCache() {
        CACHE.clear();
    }

    public static class ConformanceException extends Exception {
        public ConformanceException(String message) {
            super(message);
        }

        public ConformanceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
