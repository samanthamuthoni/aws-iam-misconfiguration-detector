import re

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


def check_passrole(statement: dict[str, Any], index: int = 1) -> Finding | None:
    """Review PassRole grants with wildcard resource scope."""
    if statement["Effect"] != "Allow" or "Resource" not in statement:
        return None

    # IAM001 already reports unconditional full administrative access.
    if check_admin_access(statement, index) is not None:
        return None

    actions = statement.get("Action", [])
    if not any(action_matches(action, "iam:PassRole") for action in actions):
        return None

    resources = statement["Resource"]
    if not any("*" in resource or "?" in resource for resource in resources):
        return None

    severity = Severity.HIGH if "*" in resources else Severity.MEDIUM
    condition_note = (
        "Conditions are present; their effectiveness has not been evaluated."
        if "Condition" in statement
        else "No conditions are present."
    )

    return Finding(
        rule_id="IAM004",
        severity=severity,
        statement_index=index,
        title="PassRole allows wildcard role selection",
        description=(
            "This statement permits passing roles selected by a wildcard. "
            "With compatible service permissions and role trust, a caller "
            "could make a service use a role with greater privileges. "
            f"{condition_note} "
            "This finding does not prove an exploitable escalation path."
        ),
        remediation=(
            "Specify approved role ARNs, restrict the destination service "
            "with iam:PassedToService where appropriate, and review the "
            "roles' permissions, trust policies, and related service access."
        ),
    )


def action_matches(pattern: str, action: str) -> bool:
    """Match IAM action names using only * and ? wildcards."""
    expression = re.escape(pattern.lower())
    expression = expression.replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, action.lower()) is not None


def check_policy_versions(statement: dict[str, Any], index: int = 1) -> Finding | None:
    """Review permissions to change managed policy versions."""
    if statement["Effect"] != "Allow" or "Resource" not in statement:
        return None

    if check_admin_access(statement, index) is not None:
        return None

    targets = (
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
    )
    actions = statement.get("Action", [])
    matched = [
        target
        for target in targets
        if any(action_matches(pattern, target) for pattern in actions)
    ]
    if not matched:
        return None

    resources = statement["Resource"]
    severity = Severity.HIGH if "*" in resources else Severity.MEDIUM
    condition_note = (
        "Conditions are present but their effectiveness is not evaluated."
        if "Condition" in statement
        else "No conditions are present."
    )

    return Finding(
        rule_id="IAM005",
        severity=severity,
        statement_index=index,
        title="Permissions can change active managed policy versions",
        description=(
            f"Matched actions: {', '.join(matched)}. "
            "CreatePolicyVersion can create a policy version and make it "
            "active; SetDefaultPolicyVersion can activate an existing "
            "version. Changes affect identities attached to the policy. "
            "If an affected policy controls the caller's access, this "
            "could enable privilege escalation. Policy contents, "
            "attachments, and effective permissions are not inspected. "
            f"{condition_note} This is a preliminary review priority, "
            "not proof of an exploitable escalation path."
        ),
        remediation=(
            "Remove unnecessary policy-version permissions. Restrict "
            "required access to approved customer-managed policy ARNs "
            "and controlled administrative roles. Review policy "
            "attachments, available versions, conditions, and applicable "
            "permission limits; monitor policy-version changes."
        ),
    )
