package io.mosip.testrig.conformance;

/**
 * Harness verdicts and how each one lands in a TestNG / EmailableReport run.
 *
 * <p>MOSIP's EmailableReport classifies skipped tests by the text of the SkipException:
 * messages containing "known issue" are counted as Known Issues (KI), messages containing
 * "feature not supported" / "Not in run scope" as Ignored (I). The {@link TestNgOutcome}
 * tells the module test class which of those buckets to use.
 */
public enum Verdict {
    PASS(TestNgOutcome.PASS),
    STALE_BENCHMARK(TestNgOutcome.PASS),
    KNOWN_ISSUE(TestNgOutcome.SKIP_KNOWN_ISSUE),
    SKIP(TestNgOutcome.SKIP_IGNORED),
    FAIL(TestNgOutcome.FAIL),
    INCOMPLETE(TestNgOutcome.FAIL);

    private final TestNgOutcome outcome;

    Verdict(TestNgOutcome outcome) {
        this.outcome = outcome;
    }

    public TestNgOutcome outcome() {
        return outcome;
    }

    public static Verdict parse(String value) {
        if (value == null || value.isBlank()) {
            return INCOMPLETE;
        }
        try {
            return Verdict.valueOf(value.trim());
        } catch (IllegalArgumentException e) {
            return INCOMPLETE;
        }
    }

    public enum TestNgOutcome {
        PASS,
        FAIL,
        /** Benchmark-expected failure linked to a tracked issue. */
        SKIP_KNOWN_ISSUE,
        /** Not applicable / skipped by the suite. */
        SKIP_IGNORED
    }
}
