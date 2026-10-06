# aws-iam-misconfiguration-detector
Python security tool for detecting risky AWS IAM policies, excessive permissions, missing safeguards, and credential hygiene issues.

## Development status

Early development. The current code runs entirely offline with local
IAM policy JSON files. No AWS account or credentials are required.

Implemented:
- JSON file loading with readable input errors.
- Statement-container and basic required permission-field validation.
- Normalization of string and list permission values.
- IAM001: detection of unconditional Allow statements containing the exact
  global wildcard in both Action and Resource.
- Structured findings with severity, statement number, explanation, and
  remediation guidance.
- Automated tests for input handling, normalization, and the first rule.

Limitations:
- This is not a complete AWS policy validator or effective-permissions evaluator.
- Statements containing Condition are deferred by IAM001; they are not
  classified as safe.
- Other security rules, condition interpretation, the command-line interface,
  JSON report export, GitHub Actions, and live AWS scanning are not implemented yet.

Tests and Ruff checks have passed locally in GitHub Codespaces.
