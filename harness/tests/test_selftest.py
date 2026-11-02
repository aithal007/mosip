from icg.refverifier import RULES
from icg.selftest import run_selftest
from icg.settings import Settings


def test_strict_reference_is_clean_and_every_mutant_is_caught():
    report = run_selftest(Settings.from_env())
    assert report.baseline_clean, report.baseline_detail
    assert report.survivors == [], f"blind spots: {report.survivors}"
    assert len(report.mutants) == len(RULES)
