from pathlib import Path

from iam_detector.analyzer import analyze_policy, load_policy
from iam_detector.models import Severity


def test_passrole_example_runs_through_analyzer():
    example = Path(__file__).resolve().parents[1] / "examples" / "passrole-broad.json"
    findings = analyze_policy(load_policy(example))

    assert len(findings) == 1
    assert findings[0].rule_id == "IAM004"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].statement_index == 1
