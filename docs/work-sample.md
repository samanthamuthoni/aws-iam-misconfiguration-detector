# AWS IAM Misconfiguration Detector — Work Sample

Author: Samantha “Nonny” Muthoni

## Status
Working early offline prototype; the full planned MVP is in development.
No AWS account, credentials, or live cloud access is required.

## Implemented features
- Basic IAM policy JSON validation and string/list normalization.
- IAM001: Unconditional global administrative Allow.
- IAM002: Broad service-level action permissions.
- IAM003: Allow statements using NotAction or NotResource.
- IAM004: Explicit PassRole with wildcard resource selection.
- Terminal and JSON reports with severity, explanations, and remediation.
- CLI exit codes and graceful input-error handling.

## Architecture
The CLI accepts a file. The analyzer loads, validates, and normalizes
statements. Independent checks produce Finding objects. The reporting
module renders those findings as text or JSON.

## Demonstration
Run these commands from the repository root with Python 3.11 or newer:

    python -m venv .venv
    source .venv/bin/activate
    python -m pip install -e . -r requirements-dev.txt
    python -m iam_detector.cli examples/passrole-broad.json
    python -m iam_detector.cli examples/admin-access.json --format json

Exit codes: 0 = no implemented findings, 1 = findings, 2 = input/usage error.

## Validation
85 tests passed locally. GitHub Actions checks passed on Python 3.11
and 3.14 for code commit d3dc331. Tests cover input handling, normalization,
rules, reporting, CLI behavior, and analyzer integration.

## Security design and limitations
Public examples use synthetic policies. Policy input is parsed as data.
The tool does not require credentials or make AWS API calls.

This is static review, not effective permission evaluation.
Conditions are not interpreted. Zero findings does not establish safety.
Severity indicates review priority, not proven exploitability.

IAM004 matches explicit PassRole actions and wildcard action patterns.
It does not analyze NotAction or NotResource. Unconditional full
administrative access is reported by IAM001 without a duplicate IAM004
finding. Role permissions, trust, and related service permissions are
not inspected.

## Future work
Broader wildcard analysis, additional escalation checks, MFA and
condition handling, and more complete policy validation.
Live AWS scanning is not implemented.


Latest local validation after the PassRole wildcard update: 94 tests passed; Ruff formatting and lint checks passed.
GitHub Actions verification for this update is pending.
