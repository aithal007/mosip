package io.mosip.testrig.conformance;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

public class ConformanceBridgeTest {

    private static final String RESULTS = """
            {
              "schemaVersion": 1,
              "run_id": "20260917000000",
              "runId": "20260917000000",
              "mode": "per-module",
              "suite_version": "release-v5.2.4",
              "components": ["verify"],
              "plans": [{"component": "verify", "plan_name": "oid4vp-1final-verifier-test-plan", "plan_id": "P1",
                         "variant": {"credential_format": "sd_jwt_vc"}, "gating": true, "plan_url": "https://suite/plan-detail.html?plan=P1"}],
              "modules": [
                {"component": "verify", "plan_name": "oid4vp-1final-verifier-test-plan", "plan_id": "P1",
                 "module_name": "oid4vp-1final-verifier-happy-flow", "module_id": "M1",
                 "variant": {"response_mode": "direct_post", "credential_format": "sd_jwt_vc"},
                 "status": "FINISHED", "suite_result": "REVIEW", "verdict": "PASS",
                 "verdict_reason": "REVIEW resolved", "issue": "", "log_url": "https://suite/log-detail.html?log=M1",
                 "findings": [], "requirements": ["OID4VP-1FINAL-8.2"],
                 "review_evidence": {"expected": "SUCCESS", "actual": "SUCCESS", "matched": true}},
                {"component": "verify", "plan_name": "oid4vp-1final-verifier-test-plan", "plan_id": "P1",
                 "module_name": "oid4vp-1final-verifier-invalid-sd-hash", "module_id": "M2",
                 "variant": {"credential_format": "sd_jwt_vc"}, "status": "FINISHED", "suite_result": "FAILED",
                 "verdict": "KNOWN_ISSUE", "verdict_reason": "1 failure(s) match the benchmark",
                 "issue": "https://github.com/inji/inji-verify/issues/1", "log_url": "",
                 "findings": [{"condition": "EnsureHttpStatusCodeIs4xx", "result": "FAILURE", "message": "<200>", "block": "", "requirements": []}]},
                {"component": "verify", "plan_name": "oid4vp-1final-verifier-test-plan", "plan_id": "P1",
                 "module_name": "oid4vp-1final-verifier-kb-jwt-iat-in-past", "module_id": "M3",
                 "status": "WAITING", "suite_result": "", "verdict": "SOMETHING_NEW", "findings": []}
              ],
              "gatePassed": true,
              "futureField": {"ignored": true}
            }
            """;

    @AfterMethod
    public void clear() {
        ConformanceRunner.clearCache();
    }

    private Path writeResults() throws Exception {
        Path file = Files.createTempFile("results", ".json");
        Files.writeString(file, RESULTS);
        return file;
    }

    @Test
    public void parsesResultsAndMapsVerdicts() throws Exception {
        ConformanceResults results = ConformanceResults.read(writeResults());
        assertEquals(results.modulesFor("verify").size(), 3);
        assertEquals(results.modules.get(0).verdictValue().outcome(), Verdict.TestNgOutcome.PASS);
        assertEquals(results.modules.get(1).verdictValue().outcome(), Verdict.TestNgOutcome.SKIP_KNOWN_ISSUE);
        // Unknown or missing verdicts must never be treated as passing.
        assertEquals(results.modules.get(2).verdictValue(), Verdict.INCOMPLETE);
        assertEquals(results.modules.get(2).verdictValue().outcome(), Verdict.TestNgOutcome.FAIL);
    }

    @Test
    public void moduleKeyMatchesPythonContract() throws Exception {
        ConformanceResults results = ConformanceResults.read(writeResults());
        String key = results.modules.get(0).key();
        assertEquals(key, "verify|oid4vp-1final-verifier-test-plan|oid4vp-1final-verifier-happy-flow|credential_format=sd_jwt_vc,response_mode=direct_post");
        assertTrue(results.find(key).isPresent());
    }

    @Test
    public void rejectsUnknownSchemaVersion() throws Exception {
        Path file = Files.createTempFile("results", ".json");
        Files.writeString(file, "{\"schemaVersion\": 99, \"modules\": []}");
        assertThrows(java.io.IOException.class, () -> ConformanceResults.read(file));
    }

    @Test
    public void runnerLoadsExistingResultsWithoutPython() throws Exception {
        ConformanceRunConfig config = ConformanceRunConfig.builder("verify").existingResults(writeResults()).build();
        ConformanceResults results = ConformanceRunner.runOrLoad(config);
        assertEquals(results.runId, "20260917000000");
        // cached for the rest of the suite
        assertTrue(ConformanceRunner.runOrLoad(config) == results);
    }

    @Test
    public void missingHarnessIsAReportedError() {
        ConformanceRunConfig config = ConformanceRunConfig.builder("certify")
                .harnessHome(Path.of("does-not-exist")).build();
        assertThrows(ConformanceRunner.ConformanceException.class, () -> ConformanceRunner.runOrLoad(config));
    }

    @Test
    public void configFromTestrigPropertiesUsesEnvEndpointForBothUrlsByDefault() {
        Map<String, String> props = Map.of(
                ConformanceRunConfig.KEY_SERVER, "https://suite:8443/",
                ConformanceRunConfig.KEY_TIMEOUT_MINUTES, "30");
        ConformanceRunConfig config = ConformanceRunConfig.fromLookup("verify", "https://injiverify.qa.mosip.net/v1/verify/", props::get);
        assertTrue(config.enabled());
        Map<String, String> env = config.harnessEnvironment();
        assertEquals(env.get("VERIFY_ADMIN_URL"), "https://injiverify.qa.mosip.net/v1/verify");
        assertEquals(env.get("VERIFY_PUBLIC_URL"), "https://injiverify.qa.mosip.net/v1/verify");
        assertEquals(env.get("CONFORMANCE_SERVER"), "https://suite:8443/");
        assertEquals(config.timeout().toMinutes(), 30);

        ConformanceRunConfig disabled = ConformanceRunConfig.fromLookup("verify", "x", Map.of(ConformanceRunConfig.KEY_ENABLED, "no")::get);
        assertFalse(disabled.enabled());
        assertThrows(IllegalArgumentException.class, () -> ConformanceRunConfig.builder("wallet"));
    }

    @Test
    public void formatterEscapesAndNamesTests() throws Exception {
        ConformanceResults results = ConformanceResults.read(writeResults());
        ConformanceResults.Module known = results.modules.get(1);
        assertEquals(ConformanceReportFormatter.testCaseName("InjiVerify", known), "InjiVerify_OIDFConformance_oid4vp_1final_verifier_invalid_sd_hash");
        assertEquals(ConformanceReportFormatter.uniqueIdentifier("InjiVerify", 3), "TC_InjiVerify_OIDFConformance_03");
        String html = ConformanceReportFormatter.html(known, results.plan("P1").orElse(null));
        assertTrue(html.contains("&lt;200&gt;"));
        assertTrue(html.contains("inji-verify/issues/1"));
        assertFalse(html.contains("<200>"));
    }
}
