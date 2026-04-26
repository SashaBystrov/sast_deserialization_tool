import argparse
import sys
from pathlib import Path

from sast_tool.analyzer import analyze_file
from sast_tool.config_loader import load_config
from sast_tool.reporter import findings_to_console, findings_to_json, findings_to_sarif


def collect_python_files(path: Path) -> list[Path]:
    if path.is_file() and path.suffix == ".py":
        return [path]

    if path.is_dir():
        return list(path.rglob("*.py"))

    return []


def run_analysis(target_path: Path, config_path: Path) -> list:
    rules = load_config(config_path)
    files = collect_python_files(target_path)

    if not files:
        raise FileNotFoundError("Файлы Python для анализа не найдены")

    findings = []

    for file_path in files:
        findings.extend(analyze_file(file_path, rules))

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SAST-инструмент для выявления уязвимостей небезопасной десериализации в Python"
    )

    parser.add_argument(
        "target",
        help="Путь к Python-файлу или директории проекта"
    )

    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Путь к YAML-конфигурации правил анализа"
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "sarif"],
        default="console",
        help="Формат вывода результатов"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Путь к файлу для сохранения отчёта"
    )

    try:
        target_path = Path(parser.parse_args().target)
        args = parser.parse_args()

        findings = run_analysis(
            target_path=Path(args.target),
            config_path=Path(args.config),
        )

        if args.format == "json":
            report = findings_to_json(findings)
        elif args.format == "sarif":
            report = findings_to_sarif(findings)
        else:
            report = findings_to_console(findings)

        if args.output:
            Path(args.output).write_text(report, encoding="utf-8")
        else:
            print(report)

        sys.exit(1 if findings else 0)

    except Exception as error:
        print(f"Ошибка выполнения анализа: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()