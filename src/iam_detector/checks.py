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


def check_service_wildcard(statement: dict[str, Any], index: int = 1) -> Finding | None:
    """Review exact service-wide action wildcards in Allow statements."""
    if statement["Effect"] != "Allow" or "Resource" not in statement:
        return None

    actions = statement.get("Action", [])
    resources = statement["Resource"]

    # IAM001 already reports this unconditional administrative pattern.
    if "*" in actions and "*" in resources and "Condition" not in statement:
        return None

    services: set[str] = set()

    for action in actions:
        service, separator, operation = action.partition(":")
        if separator and service and operation == "*":
            services.add(service.lower())

    if not services:
        return None

    if "*" in resources:
        severity = Severity.HIGH
        scope_note = "Resource includes the exact global wildcard. "
    else:
        severity = Severity.MEDIUM
        scope_note = (
            "Resource has no exact global wildcard; its ARN scope still needs review. "
        )

    condition_note = (
        "Conditions are present; their effectiveness has not been evaluated."
        if "Condition" in statement
        else "No conditions are present."
    )

    return Finding(
        rule_id="IAM002",
        severity=severity,
        statement_index=index,
        title=f"Broad service permissions: {', '.join(sorted(services))}",
        description=(
            "Service-wide action wildcards may permit reading, changing, "
            "or deleting resources, depending on the service and applicable "
            "resource permissions. " + scope_note + condition_note
        ),
        remediation=(
            "Replace service-wide action wildcards with the required actions. "
            "Scope resources where supported and review applicable conditions."
        ),
    )


def check_allow_exclusions(statement: dict[str, Any], index: int = 1) -> Finding | None:
    """Review Allow statements that use permission exclusions."""
    if statement["Effect"] != "Allow":
        return None

    exclusions = [key for key in ("NotAction", "NotResource") if key in statement]
    if not exclusions:
        return None

    # Excluding everything leaves nothing allowed in that dimension.
    if any("*" in statement[key] for key in exclusions):
        return None

    broad_resources = "NotResource" in statement or "*" in statement.get("Resource", [])
    severity = Severity.HIGH if broad_resources else Severity.MEDIUM

    notes = []
    if "NotAction" in statement:
        notes.append(
            "NotAction allows applicable actions outside its exclusion list. "
            "Resource scope still limits which actions are applicable."
        )
    if "NotResource" in statement:
        notes.append(
            "NotResource applies the allowed actions to applicable resources "
            "outside its exclusion list."
        )
    if "Condition" in statement:
        notes.append(
            "Conditions are present; their effectiveness has not been evaluated."
        )
    else:
        notes.append("No conditions are present.")

    notes.append(
        "This review priority is preliminary. Effective access depends on "
        "other policies, explicit denies, and applicable permission limits."
    )

    return Finding(
        rule_id="IAM003",
        severity=severity,
        statement_index=index,
        title=f"Allow statement uses {', '.join(exclusions)}",
        description=" ".join(notes),
        remediation=(
            "Prefer explicit Action and Resource allowlists for the workload. "
            "If exclusions are necessary, review their scope and conditions "
            "and test intended access."
        ),
    )
