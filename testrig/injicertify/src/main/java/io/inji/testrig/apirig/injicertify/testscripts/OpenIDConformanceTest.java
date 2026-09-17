package io.inji.testrig.apirig.injicertify.testscripts;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.testng.ITest;
import org.testng.ITestContext;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import io.inji.testrig.apirig.injicertify.utils.InjiCertifyConfigManager;
import io.inji.testrig.apirig.injicertify.utils.InjiCertifyUtil;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.conformance.ConformanceReportFormatter;
import io.mosip.testrig.conformance.ConformanceResults;
import io.mosip.testrig.conformance.ConformanceRunConfig;
import io.mosip.testrig.conformance.ConformanceRunner;
import io.mosip.testrig.conformance.ConformanceRunner.ConformanceException;

/**
 * Runs the OpenID Foundation OID4VCI issuer test plan against the Inji Certify instance this
 * testrig targets ({@code env.endpoint}) and reports one TestNG result per conformance module
 * in the regular EmailableReport.
 *
 * <p>Verdicts come from the Inji Conformance Gate benchmark: regressions fail, benchmark-expected
 * failures are reported as known issues with their tracking link, and suite-skipped modules as
 * ignored.
 */
public class OpenIDConformanceTest extends InjiCertifyUtil implements ITest {

	private static final Logger logger = Logger.getLogger(OpenIDConformanceTest.class);
	private static final String COMPONENT = "certify";
	private static final String PREFIX = "InjiCertify";
	private static final String INFRASTRUCTURE_CASE = "INFRASTRUCTURE";

	protected String testCaseName = "";
	private ConformanceResults results;
	private String infrastructureError;

	@BeforeClass
	public static void setLogLevel() {
		logger.setLevel(InjiCertifyConfigManager.IsDebugEnabled() ? Level.ALL : Level.ERROR);
	}

	@Override
	public String getTestName() {
		return testCaseName;
	}

	@DataProvider(name = "testcaselist")
	public Object[] getTestCaseList(ITestContext context) {
		// Same target as SimplePost: ApplnURI is env.endpoint.
		ConformanceRunConfig config = ConformanceRunConfig.fromLookup(COMPONENT, ApplnURI + "/v1/certify",
				InjiCertifyConfigManager::getproperty);
		List<TestCaseDTO> cases = new ArrayList<>();
		if (!config.enabled()) {
			cases.add(placeholder(PREFIX + "_OIDFConformance_Disabled", "OpenID conformance disabled (conformanceEnabled=no)"));
			return cases.toArray();
		}
		try {
			results = ConformanceRunner.runOrLoad(config);
		} catch (ConformanceException e) {
			logger.error("OpenID conformance run failed: " + e.getMessage(), e);
			infrastructureError = e.getMessage();
			cases.add(placeholder(PREFIX + "_OIDFConformance_" + INFRASTRUCTURE_CASE, "Conformance harness could not complete"));
			return cases.toArray();
		}
		int index = 1;
		for (ConformanceResults.Module module : results.modulesFor(COMPONENT)) {
			TestCaseDTO dto = new TestCaseDTO();
			dto.setTestCaseName(ConformanceReportFormatter.testCaseName(PREFIX, module));
			dto.setUniqueIdentifier(ConformanceReportFormatter.uniqueIdentifier(PREFIX, index++));
			dto.setDescription(ConformanceReportFormatter.description(module));
			dto.setEndPoint(module.log_url);
			dto.setInput(module.key());
			cases.add(dto);
		}
		return cases.toArray();
	}

	@Test(dataProvider = "testcaselist")
	public void test(TestCaseDTO testCaseDTO) throws AdminTestException {
		testCaseName = testCaseDTO.getTestCaseName();
		testCaseDTO = InjiCertifyUtil.isTestCaseValidForExecution(testCaseDTO);
		if (HealthChecker.signalTerminateExecution) {
			throw new SkipException(GlobalConstants.TARGET_ENV_HEALTH_CHECK_FAILED + HealthChecker.healthCheckFailureMapS);
		}
		if (testCaseName.endsWith("_Disabled")) {
			throw new SkipException(GlobalConstants.NOT_IN_RUN_SCOPE_MESSAGE);
		}
		if (testCaseName.endsWith(INFRASTRUCTURE_CASE)) {
			throw new AdminTestException("OpenID conformance harness error: " + infrastructureError);
		}

		String key = testCaseDTO.getInput();
		ConformanceResults.Module module = results.find(key)
				.orElseThrow(() -> new AdminTestException("Conformance module missing from results: " + key));
		Reporter.log(ConformanceReportFormatter.html(module, results.plan(module.plan_id).orElse(null)));

		String detail = module.module_name + ": " + module.verdict_reason;
		switch (module.verdictValue().outcome()) {
		case PASS:
			return;
		case SKIP_KNOWN_ISSUE:
			// EmailableReport counts messages containing "known issue" in the KI column.
			throw new SkipException(GlobalConstants.KNOWN_ISSUES + " " + module.issue + " (" + detail + ")");
		case SKIP_IGNORED:
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE + " (" + detail + ")");
		case FAIL:
		default:
			throw new AdminTestException("OpenID conformance " + module.verdict + " - " + detail);
		}
	}

	private static TestCaseDTO placeholder(String name, String description) {
		TestCaseDTO dto = new TestCaseDTO();
		dto.setTestCaseName(name);
		dto.setUniqueIdentifier("TC_" + name);
		dto.setDescription(description);
		dto.setInput("");
		return dto;
	}

	@AfterMethod(alwaysRun = true)
	public void setResultTestName(ITestResult result) {
		result.setAttribute("TestCaseName", testCaseName);
	}
}
