import json
from .models import Finding



SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

TOOL_NAME = "Python Unsafe Deserialization SAST"
TOOL_INFORMATION_URI = "https://example.local"

DEFAULT_RULE_ID = "sast.python.unsafe_deserialization"

CLR = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "END": "\033[0m",
    "BOLD": "\033[1m",
}


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

    header_line = "=" * 72
    lines.append(f"{CLR['HEADER']}{header_line}")
    lines.append(f"PYTHON UNSAFE DESERIALIZATION SAST REPORT")
    lines.append(f"{header_line}{CLR['END']}")

    if not findings:
        lines.append(f"{CLR['GREEN']}Result: No vulnerabilities found.{CLR['END']}")
        lines.append(f"{CLR['HEADER']}{header_line}{CLR['END']}")
        return "\n".join(lines)

    lines.append(f"{CLR['BOLD']}Total findings: {len(findings)}{CLR['END']}")
    lines.append("-" * 72)

    for index, finding in enumerate(findings, start=1):
        lines.append(f"{CLR['RED']}{CLR['BOLD']}[{index}] {finding.description}{CLR['END']}")

        lines.append(f"    {CLR['CYAN']}File:{CLR['END']}      {finding.file_path}")
        lines.append(f"    {CLR['CYAN']}Line:{CLR['END']}      {finding.line_number}")
        lines.append(f"    {CLR['CYAN']}Library:{CLR['END']}   {finding.library_name}")
        lines.append(f"    {CLR['CYAN']}Function:{CLR['END']}  {finding.function_name}")
        lines.append(f"    {CLR['CYAN']}Resolved:{CLR['YELLOW']} {finding.resolved_function_name}{CLR['END']}")
        lines.append(f"    {CLR['CYAN']}Severity:{CLR['END']}  {CLR['RED']}{finding.severity}{CLR['END']}")

        if finding.taint_trace:
            lines.append(f"    {CLR['BLUE']}Taint Trace:{CLR['END']}")
            path_elements = [f"{CLR['BOLD']}{node}{CLR['END']}" for node in finding.taint_trace]
            trace_visualization = f" {CLR['BLUE']}→{CLR['END']} ".join(path_elements)
            lines.append(f"    {trace_visualization}")

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
        "level": "error",
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