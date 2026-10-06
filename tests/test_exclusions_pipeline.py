"""Verify exclusion detection through file loading and analysis."""

from pathlib import Path

from iam_detector.analyzer import analyze_policy, load_policy
from iam_detector.models import Severity


def test_exclusions_example_produces_two_findings():
    example = Path(__file__).resolve().parents[1] / "examples" / "allow-exclusions.json"
    findings = analyze_policy(load_policy(example))

    assert len(findings) == 2
    assert [finding.rule_id for finding in findings] == ["IAM003", "IAM003"]
    assert [finding.statement_index for finding in findings] == [1, 2]
    assert all(finding.severity == Severity.HIGH for finding in findings)
