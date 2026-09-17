package io.mosip.testrig.conformance;

import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Settings for one conformance run launched from a testrig.
 *
 * <p>Build it with {@link #fromLookup(String, String, Function)} passing the module's
 * ConfigManager lookup, so every key follows the testrig convention of being overridable
 * by an environment variable of the same name.
 */
public final class ConformanceRunConfig {

    public static final String KEY_ENABLED = "conformanceEnabled";
    public static final String KEY_HARNESS_HOME = "conformanceHarnessHome";
    public static final String KEY_PYTHON = "conformancePython";
    public static final String KEY_SERVER = "conformanceServer";
    public static final String KEY_PUBLIC_BASE_URL = "conformancePublicBaseUrl";
    public static final String KEY_RESULTS_FILE = "conformanceResultsFile";
    public static final String KEY_OUTPUT_DIR = "conformanceOutputDir";
    public static final String KEY_TIMEOUT_MINUTES = "conformanceTimeoutMinutes";
    public static final String KEY_REVIEW_POLICY = "conformanceReviewPolicy";
    public static final String KEY_SEED = "conformanceSeedCertify";

    private final String component;
    private final boolean enabled;
    private final Path harnessHome;
    private final String python;
    private final String conformanceServer;
    private final String adminUrl;
    private final String publicUrl;
    private final Path existingResults;
    private final Path outputDir;
    private final Duration timeout;
    private final String reviewPolicy;
    private final boolean seedCertify;

    private ConformanceRunConfig(Builder b) {
        this.component = Objects.requireNonNull(b.component, "component");
        this.enabled = b.enabled;
        this.harnessHome = b.harnessHome;
        this.python = b.python;
        this.conformanceServer = b.conformanceServer;
        this.adminUrl = b.adminUrl;
        this.publicUrl = b.publicUrl;
        this.existingResults = b.existingResults;
        this.outputDir = b.outputDir;
        this.timeout = b.timeout;
        this.reviewPolicy = b.reviewPolicy;
        this.seedCertify = b.seedCertify;
    }

    /**
     * @param component    "certify" or "verify"
     * @param adminBaseUrl the component URL the testrig already targets, e.g. env.endpoint + "/v1/verify"
     * @param lookup       property lookup (ConfigManager::getproperty); may return null or blank
     */
    public static ConformanceRunConfig fromLookup(String component, String adminBaseUrl, Function<String, String> lookup) {
        Function<String, String> get = key -> {
            String value = lookup.apply(key);
            return value == null ? "" : value.trim();
        };
        Builder builder = builder(component)
                .enabled(!"no".equalsIgnoreCase(get.apply(KEY_ENABLED)) && !"false".equalsIgnoreCase(get.apply(KEY_ENABLED)))
                .adminUrl(adminBaseUrl)
                .publicUrl(get.apply(KEY_PUBLIC_BASE_URL).isEmpty() ? adminBaseUrl : get.apply(KEY_PUBLIC_BASE_URL))
                .conformanceServer(get.apply(KEY_SERVER))
                .python(get.apply(KEY_PYTHON).isEmpty() ? "python3" : get.apply(KEY_PYTHON))
                .reviewPolicy(get.apply(KEY_REVIEW_POLICY))
                .seedCertify(!"no".equalsIgnoreCase(get.apply(KEY_SEED)));
        if (!get.apply(KEY_HARNESS_HOME).isEmpty()) {
            builder.harnessHome(Path.of(get.apply(KEY_HARNESS_HOME)));
        }
        if (!get.apply(KEY_RESULTS_FILE).isEmpty()) {
            builder.existingResults(Path.of(get.apply(KEY_RESULTS_FILE)));
        }
        if (!get.apply(KEY_OUTPUT_DIR).isEmpty()) {
            builder.outputDir(Path.of(get.apply(KEY_OUTPUT_DIR)));
        }
        if (!get.apply(KEY_TIMEOUT_MINUTES).isEmpty()) {
            builder.timeout(Duration.ofMinutes(Long.parseLong(get.apply(KEY_TIMEOUT_MINUTES))));
        }
        return builder.build();
    }

    /** Environment passed to the harness process (see harness/icg/settings.py). */
    public Map<String, String> harnessEnvironment() {
        Map<String, String> env = new LinkedHashMap<>();
        String prefix = component.toUpperCase();
        putIfPresent(env, prefix + "_ADMIN_URL", stripSlash(adminUrl));
        putIfPresent(env, prefix + "_PUBLIC_URL", stripSlash(publicUrl));
        putIfPresent(env, "CONFORMANCE_SERVER", conformanceServer);
        putIfPresent(env, "ICG_REVIEW_POLICY", reviewPolicy);
        env.put("PYTHONUNBUFFERED", "1");
        return env;
    }

    private static void putIfPresent(Map<String, String> env, String key, String value) {
        if (value != null && !value.isBlank()) {
            env.put(key, value);
        }
    }

    private static String stripSlash(String url) {
        return url == null ? null : url.replaceAll("/+$", "");
    }

    public static Builder builder(String component) {
        return new Builder(component);
    }

    public String component() { return component; }
    public boolean enabled() { return enabled; }
    public Path harnessHome() { return harnessHome; }
    public String python() { return python; }
    public String adminUrl() { return adminUrl; }
    public String publicUrl() { return publicUrl; }
    public Path existingResults() { return existingResults; }
    public Path outputDir() { return outputDir; }
    public Duration timeout() { return timeout; }
    public boolean seedCertify() { return seedCertify; }

    public static final class Builder {
        private final String component;
        private boolean enabled = true;
        private Path harnessHome = Path.of(System.getProperty("user.dir"), "conformance-harness");
        private String python = "python3";
        private String conformanceServer;
        private String adminUrl;
        private String publicUrl;
        private Path existingResults;
        private Path outputDir = Path.of(System.getProperty("java.io.tmpdir"), "inji-conformance");
        private Duration timeout = Duration.ofMinutes(90);
        private String reviewPolicy;
        private boolean seedCertify = true;

        private Builder(String component) {
            if (!"certify".equals(component) && !"verify".equals(component)) {
                throw new IllegalArgumentException("component must be certify or verify, got " + component);
            }
            this.component = component;
        }

        public Builder enabled(boolean v) { this.enabled = v; return this; }
        public Builder harnessHome(Path v) { this.harnessHome = v; return this; }
        public Builder python(String v) { this.python = v; return this; }
        public Builder conformanceServer(String v) { this.conformanceServer = v; return this; }
        public Builder adminUrl(String v) { this.adminUrl = v; return this; }
        public Builder publicUrl(String v) { this.publicUrl = v; return this; }
        public Builder existingResults(Path v) { this.existingResults = v; return this; }
        public Builder outputDir(Path v) { this.outputDir = v; return this; }
        public Builder timeout(Duration v) { this.timeout = v; return this; }
        public Builder reviewPolicy(String v) { this.reviewPolicy = v; return this; }
        public Builder seedCertify(boolean v) { this.seedCertify = v; return this; }

        public ConformanceRunConfig build() {
            return new ConformanceRunConfig(this);
        }
    }
}
