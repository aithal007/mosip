# api-testrig integration

The Inji api-testrigs live in each product repository (`inji/inji-certify/api-test`, `inji/inji-verify/api-test`). They are built on `apitest-commons` from `mosip-functional-tests` with **Java 21** and TestNG 7. Their reports come from `io.mosip.testrig.apirig.report.EmailableReport` and are uploaded to the S3/MinIO bucket configured by `s3-account` (the `automationtests` bucket in MOSIP deployments).

`OpenIDConformanceTest` follows the existing test-script conventions (`SimplePost` and others):
- It `extends InjiCertifyUtil` / `InjiVerifyUtil` and `implements ITest`.
- A `@DataProvider(name = "testcaselist")` returns one `TestCaseDTO` per conformance module.
- `isTestCaseValidForExecution` is called, so `testCaseSkippedList.txt` and `testCasesToExecute` still apply.
- An `@AfterMethod` sets the `TestCaseName` attribute.
- `Reporter.log` writes an HTML snippet (module, plan and suite log links, verdict, issue, review evidence, findings), which EmailableReport renders inline.

| Harness verdict | TestNG outcome | EmailableReport bucket |
|---|---|---|
| PASS, STALE_BENCHMARK | pass | P |
| KNOWN_ISSUE | `SkipException(GlobalConstants.KNOWN_ISSUES + issue)` | KI |
| SKIP | `SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE)` | I |
| FAIL, INCOMPLETE, unknown | `AdminTestException` | F |
| Harness could not run | one `…_OIDFConformance_INFRASTRUCTURE` failure | F |

The class targets **the same URL the testrig already uses**: `ApplnURI` (`env.endpoint`) for Certify and `injiVerifyBaseUrl` for Verify. Those URLs are passed to the harness as the component's admin and public URL.

## Steps (Inji Verify; Certify is identical with `injicertify` names)

1. **Library:** `cd testrig/conformance-bridge && mvn install`, or publish it to your Maven repository. Then add it to `api-test/pom.xml`:
   ```xml
   <dependency>
     <groupId>io.mosip.testrig</groupId>
     <artifactId>conformance-bridge</artifactId>
     <version>0.1.0</version>
   </dependency>
   ```
2. **Test class:** copy `testrig/injiverify/src/main/java/io/inji/testrig/apirig/injiverify/testscripts/OpenIDConformanceTest.java` into the same package.
3. **Suite:** copy `testrig/injiverify/testNgXmlFiles/injiverifyConformanceSuite.xml` next to the master suite and include it:
   ```xml
   <suite-file path="injiverifyConformanceSuite.xml" />
   ```
   `InjiTestRunner` only launches files whose name contains `mastertestsuite`, so the conformance suite has to be included from the master suite.
4. **Properties:** append `testrig/conformance.properties` to `src/main/resources/config/injiVerify.properties`. Every key can be overridden by an environment variable of the same name, which is how the apitestrig Helm chart injects values.
5. **Image:** build the Python-enabled layer on top of the testrig image:
   ```bash
   docker build -f testrig/Dockerfile.conformance-layer \
     --build-arg BASE_IMAGE=injistack/apitest-inji-verify:1.0.0-alpha.1 -t apitest-inji-verify-conformance .
   ```
6. **Deployment:** point `conformanceServer` at a conformance suite reachable from the cluster. The suite must be able to reach the component's public https URL.
   - An alternative is to run the harness as a separate CI job and set `conformanceResultsFile` to its `results.json`. The testrig then only reports the results, and needs no Python and no suite access.

## Per-module and combined modes

- **Per-module (default).** Each testrig runs only its own component (`--component certify` or `--component verify`), so each module's gate is independent, as the testrigs are today.
- **Combined.** `./run-full-stack-conformance.sh` (or `icg run --combined --parallel`) produces one consolidated cross-module report, badge and gate. The combined `results.json` can also be fed to both testrigs with `conformanceResultsFile`.

## Verified

- `testrig/conformance-bridge` builds with its TestNG unit tests on JDK 21. The tests cover parsing, verdict mapping, the fail-closed behaviour for unknown verdicts, escaping, and config from testrig properties.
- Both `OpenIDConformanceTest` classes compile inside unmodified copies of the `release-1.0.x` api-test modules, with only the dependency added:
  - `inji/inji-verify` against `apitest-commons` 1.5.0
  - `inji/inji-certify` against `apitest-commons` 1.6.0

  Two build notes apply to the upstream api-test poms, not to this code:
  - **Retired `ossrh` repository.** The poms declare the `ossrh` snapshot repository, and `oss.sonatype.org` has been retired, so dependency resolution fails. Mirror it to Maven Central in `settings.xml` (`<mirrorOf>ossrh</mirrorOf>` → `https://repo.maven.apache.org/maven2`).
  - **git-commit-id plugin.** Outside a git checkout, add `-Dmaven.gitcommitid.skip=true`.
