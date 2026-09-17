package io.mosip.testrig.conformance;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Java view of the harness {@code results.json} contract (schemaVersion 1).
 * Unknown fields are ignored so newer harness versions stay readable.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ConformanceResults {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public int schemaVersion;
    public String runId;
    public String mode;
    public String suiteVersion;
    public List<String> components = new ArrayList<>();
    public List<Plan> plans = new ArrayList<>();
    public List<Module> modules = new ArrayList<>();
    public Map<String, Integer> gatingSummary;
    public boolean gatePassed;

    public static ConformanceResults read(Path file) throws IOException {
        ConformanceResults results = MAPPER.readValue(file.toFile(), ConformanceResults.class);
        if (results.schemaVersion != 1) {
            throw new IOException("Unsupported results schemaVersion " + results.schemaVersion + " in " + file);
        }
        return results;
    }

    public List<Module> modulesFor(String component) {
        return modules.stream().filter(m -> component.equals(m.component)).toList();
    }

    public Optional<Module> find(String key) {
        return modules.stream().filter(m -> m.key().equals(key)).findFirst();
    }

    public Optional<Plan> plan(String planId) {
        return plans.stream().filter(p -> planId != null && planId.equals(p.plan_id)).findFirst();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Plan {
        public String component;
        public String plan_name;
        public String plan_id;
        public Map<String, String> variant;
        public boolean gating;
        public String plan_url;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Finding {
        public String condition;
        public String result;
        public String message;
        public String block;
        public List<String> requirements = new ArrayList<>();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Module {
        public String component;
        public String plan_name;
        public String plan_id;
        public String module_name;
        public String module_id;
        public Map<String, String> variant;
        public String status;
        public String suite_result;
        public String verdict;
        public String verdict_reason;
        public String issue;
        public double duration_seconds;
        public String log_url;
        public List<Finding> findings = new ArrayList<>();
        public List<String> requirements = new ArrayList<>();
        public Map<String, Object> review_evidence;

        /** Stable identity, same as the Python ModuleResult.key. */
        public String key() {
            StringBuilder variantText = new StringBuilder();
            if (variant != null) {
                variant.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
                    if (variantText.length() > 0) {
                        variantText.append(',');
                    }
                    variantText.append(e.getKey()).append('=').append(e.getValue());
                });
            }
            return component + "|" + plan_name + "|" + module_name + "|" + variantText;
        }

        public Verdict verdictValue() {
            return Verdict.parse(verdict);
        }
    }
}
