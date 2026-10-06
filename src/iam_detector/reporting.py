"""Text and JSON reports for offline policy findings."""

import json
from dataclasses import asdict

from iam_detector.models import Finding

REPORT_SCOPE = (
    "Implemented static checks only. Effective AWS permissions are not "
    "evaluated; zero findings is not a guarantee of safety."
)


def render_text(findings: list[Finding]) -> str:
    """Format findings for a person reading the terminal."""
    lines = [f"Findings: {len(findings)}", REPORT_SCOPE]

    if not findings:
        lines.append("No findings from the implemented checks.")

    for finding in findings:
        lines.extend(
            [
                "",
                f"[{finding.severity.value}] {finding.rule_id}: {finding.title}",
                f"Statement: {finding.statement_index}",
                f"Why: {finding.description}",
                f"Fix: {finding.remediation}",
            ]
        )

    return "\n".join(lines)


def render_json(findings: list[Finding]) -> str:
    """Format findings as a structured JSON report."""
    entries = []

    for finding in findings:
        entry = asdict(finding)
        entry["severity"] = finding.severity.value
        entries.append(entry)

    report = {
        "schema_version": 1,
        "finding_count": len(findings),
        "findings": entries,
        "scope": REPORT_SCOPE,
    }

    return json.dumps(report, indent=2)
