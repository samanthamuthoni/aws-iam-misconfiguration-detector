# aws-iam-misconfiguration-detector

[![CI](https://github.com/samanthamuthoni/aws-iam-misconfiguration-detector/actions/workflows/ci.yml/badge.svg?branch=feat%2Foffline-analysis&event=push)](https://github.com/samanthamuthoni/aws-iam-misconfiguration-detector/actions/workflows/ci.yml)
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
- IAM002: service-wide action checks with preliminary resource-based severity.
- Readable text reports and structured JSON reports.
- Command-line interface with report-format selection and exit codes.
- Automated tests for input handling, security checks, reports, and CLI behavior.

Limitations:
- This is not a complete AWS policy validator or effective-permissions evaluator.
- Statements containing Condition are deferred by IAM001; they are not
  classified as safe.
- Remaining security rules, condition interpretation, and live AWS
  scanning are not implemented yet.
- IAM002 severity is a preliminary review priority. ARN breadth and
  condition effectiveness still require deeper analysis.

Tests and Ruff checks passed locally in GitHub Codespaces and in GitHub
Actions on Python 3.11 and 3.14 for commit `6605f90`.


## Local setup

Run these commands from the repository root in Linux or GitHub Codespaces.
The package requires Python 3.11 or newer; local verification currently uses
Python 3.14.2.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e . -r requirements-dev.txt
```

## Usage

Display a readable report for the synthetic administrative-access example:

```bash
python -m iam_detector.cli examples/admin-access.json
```

Display a structured JSON report:

```bash
python -m iam_detector.cli examples/admin-access.json --format json
```

Show available arguments:

```bash
python -m iam_detector.cli --help
```

Reports go to standard output. Input errors go to standard error.

| Exit code | Meaning |
|---|---|
| 0 | No findings from the implemented checks |
| 1 | Findings detected |
| 2 | Invalid input, unreadable file, or invalid command-line arguments |

The administrative-access example intentionally returns 1.
Zero findings does not establish that a policy is safe.

## Local quality checks

```bash
python -m ruff format --check src tests
python -m ruff check src tests
python -m pytest -q
```

### Allow statements with exclusions (IAM003)

IAM003 reviews Allow statements that use NotAction or NotResource.
These exclusions can grant permissions beyond the actions or resources
a policy author intended.

Severity is a preliminary review priority. Conditions and effective AWS
permissions are not evaluated. Deny statements are not flagged by this rule.

Run the synthetic example:

```bash
python -m iam_detector.cli examples/allow-exclusions.json
```

Local validation: 76 tests passed, along with Ruff formatting and lint checks.

### Wildcard role selection with PassRole (IAM004)

IAM004 reviews Allow statements whose Action matches iam:PassRole,
including wildcard patterns such as iam:*, iam:Pass*, and IAM:PassRol?.
It assigns High priority for Resource "*" and Medium priority for
other resource patterns containing "*" or "?".

The rule reports conditions without evaluating their effectiveness.
It does not inspect role permissions, role trust, or related service
permissions, so a finding does not prove an exploitable escalation path.

Current limitations: IAM004 does not analyze NotAction or NotResource.
Unconditional full administrative access is reported by IAM001 instead
of generating an overlapping IAM004 finding. An exact role
ARN receiving no IAM004 finding does not establish that the role is safe.

Run the synthetic example:

```bash
python -m iam_detector.cli examples/passrole-broad.json
```

Local validation after adding IAM004: 85 tests passed, along with Ruff
formatting and lint checks.


Latest local validation after the PassRole wildcard update: 94 tests passed; Ruff formatting and lint checks passed.
GitHub Actions verification for this update is pending.
