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
        lines.append(f"    Файл:      {finding.file}")
        lines.append(f"    Строка:    {finding.line}")
        lines.append(f"    Библиотека:{finding.library}")
        lines.append(f"    Функция:   {finding.function}")
        lines.append("-" * 70)

    return "\n".join(lines)