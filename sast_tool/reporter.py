import json
from dataclasses import asdict

from .models import Finding


def findings_to_json(findings: list[Finding]) -> str:
    report = {
        "summary": {
            "total_findings": len(findings)
        },
        "findings": [asdict(finding) for finding in findings],
    }

    return json.dumps(report, ensure_ascii=False, indent=2)


def findings_to_console(findings: list[Finding]) -> str:
    lines = []

    lines.append("=" * 70)
    lines.append("SAST-анализ небезопасной десериализации")
    lines.append("=" * 70)

    if not findings:
        lines.append("Результат: уязвимости не обнаружены.")
        lines.append("=" * 70)
        return "\n".join(lines)

    lines.append(f"Обнаружено уязвимостей: {len(findings)}")
    lines.append("-" * 70)

    for index, finding in enumerate(findings, start=1):
        lines.append(f"[{index}] {finding.description}")
        lines.append(f"    Файл:       {finding.file}")
        lines.append(f"    Строка:     {finding.line}")
        lines.append(f"    Библиотека: {finding.library}")
        lines.append(f"    Функция:    {finding.function}")
        lines.append("-" * 70)

    return "\n".join(lines)


def findings_to_sarif(findings: list[Finding]) -> str:
    results = []

    for finding in findings:
        results.append({
            "ruleId": "PY_UNSAFE_DESERIALIZATION",
            "level": "error",
            "message": {
                "text": finding.description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file
                        },
                        "region": {
                            "startLine": finding.line
                        }
                    }
                }
            ],
            "properties": {
                "library": finding.library,
                "function": finding.function
            }
        })

    sarif_report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Python Unsafe Deserialization SAST",
                        "informationUri": "https://example.local",
                        "rules": [
                            {
                                "id": "PY_UNSAFE_DESERIALIZATION",
                                "name": "Unsafe deserialization of untrusted data",
                                "shortDescription": {
                                    "text": "Передача недоверенных данных в функцию десериализации"
                                },
                                "fullDescription": {
                                    "text": "Обнаружен потенциально опасный вызов функции десериализации, аргумент которой зависит от недоверенного источника данных."
                                },
                                "help": {
                                    "text": "Необходимо исключить передачу недоверенных данных в функции десериализации либо использовать безопасные механизмы обработки данных."
                                },
                                "properties": {
                                    "problem.severity": "error",
                                    "security-severity": "8.0",
                                    "tags": [
                                        "security",
                                        "deserialization",
                                        "python"
                                    ]
                                }
                            }
                        ]
                    }
                },
                "results": results
            }
        ]
    }

    return json.dumps(sarif_report, ensure_ascii=False, indent=2)