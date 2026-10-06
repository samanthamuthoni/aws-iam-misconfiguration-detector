"""Security checks for normalized IAM permission statements."""

from typing import Any

from iam_detector.models import Finding, Severity


def check_admin_access(statement: dict[str, Any], index: int = 1) -> Finding | None:
    """Find unconditional Allow statements with exact global wildcards."""
    if statement["Effect"] != "Allow":
        return None

    # Condition interpretation will be implemented separately.
    if "Condition" in statement:
        return None

    actions = statement.get("Action", [])
    resources = statement.get("Resource", [])

    if "*" not in actions or "*" not in resources:
        return None

    return Finding(
        rule_id="IAM001",
        severity=Severity.CRITICAL,
        statement_index=index,
        title="Unconditional administrative Allow statement",
        description=(
            "This statement allows every action on every resource without "
            "conditions. It could permit destructive changes and permission "
            "management. Effective access still depends on other policies, "
            "explicit denies, and applicable permission limits."
        ),
        remediation=(
            "Replace global wildcards with the actions and resources needed "
            "for the workload. Separate administrative duties into a tightly "
            "controlled role."
        ),
    )
