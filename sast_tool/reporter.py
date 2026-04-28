import json

from .models import Finding


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

TOOL_NAME = "Python Unsafe Deserialization SAST"
TOOL_INFORMATION_URI = "https://example.local"

DEFAULT_RULE_ID = "sast.python.unsafe_deserialization"


def findings_to_json(findings: list[Finding]) -> str:
    report = {
        "summary": {
            "total_findings": len(findings)
        },
        "findings": [finding.to_dict() for finding in findings],
    }

    return json.dumps(report, ensure_ascii=False, indent=2)


def findings_to_console(findings: list[Finding]) -> str:
    lines: list[str] = []

    lines.append("=" * 72)
    lines.append("Unsafe Deserialization SAST Report")
    lines.append("=" * 72)

    if not findings:
        lines.append("Result: no vulnerabilities found.")
        lines.append("=" * 72)
        return "\n".join(lines)

    lines.append(f"Total findings: {len(findings)}")
    lines.append("-" * 72)

    for index, finding in enumerate(findings, start=1):
        lines.append(f"[{index}] {finding.description}")
        lines.append(f"    File:     {finding.file_path}")
        lines.append(f"    Line:     {finding.line_number}")
        lines.append(f"    Library:  {finding.library_name}")
        lines.append(f"    Function: {finding.function_name}")
        lines.append(f"    Resolved: {finding.resolved_function_name}")
        lines.append(f"    Severity: {finding.severity}")
        lines.append(f"    Rule ID:  {finding.rule_id}")
        lines.append("-" * 72)

    return "\n".join(lines)


def findings_to_sarif(findings: list[Finding]) -> str:
    sarif_report = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": [
                            build_sarif_rule()
                        ],
                    }
                },
                "results": [
                    finding_to_sarif_result(finding)
                    for finding in findings
                ],
            }
        ],
    }

    return json.dumps(sarif_report, ensure_ascii=False, indent=2)


def build_sarif_rule() -> dict:
    return {
        "id": DEFAULT_RULE_ID,
        "name": "Unsafe deserialization of untrusted data",
        "shortDescription": {
            "text": "Untrusted data is passed to a deserialization function"
        },
        "fullDescription": {
            "text": (
                "The analyzer detected a deserialization function call whose "
                "argument depends on an untrusted data source."
            )
        },
        "help": {
            "text": (
                "Avoid passing untrusted data to unsafe deserialization functions. "
                "Use safe formats or validated input where possible."
            )
        },
        "properties": {
            "problem.severity": "error",
            "security-severity": "8.0",
            "precision": "high",
            "tags": [
                "security",
                "deserialization",
                "python",
                "CWE-502"
            ],
        },
    }


def finding_to_sarif_result(finding: Finding) -> dict:
    return {
        "ruleId": finding.rule_id,
        "level": sarif_level_from_severity(finding.severity),
        "message": {
            "text": finding.description
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path
                    },
                    "region": {
                        "startLine": finding.line_number
                    },
                }
            }
        ],
        "properties": {
            "library": finding.library_name,
            "function": finding.function_name,
            "resolved_function": finding.resolved_function_name,
            "severity": finding.severity,
            "cwe": "CWE-502",
        },
    }


def sarif_level_from_severity(severity: str) -> str:
    severity_mapping = {
        "LOW": "note",
        "MEDIUM": "warning",
        "HIGH": "error",
        "CRITICAL": "error",
    }

    return severity_mapping.get(severity.upper(), "warning")