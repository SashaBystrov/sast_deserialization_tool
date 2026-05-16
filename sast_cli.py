import argparse
import sys
from pathlib import Path

from sast_tool.analyzer import analyze_file
from sast_tool.config_loader import load_analysis_config
from sast_tool.reporter import (
    findings_to_console,
    findings_to_json,
    findings_to_sarif,
)


def collect_python_files(target_path: Path) -> list[Path]:
    if target_path.is_file() and target_path.suffix == ".py":
        return [target_path]

    if target_path.is_dir():
        return list(target_path.rglob("*.py"))

    return []


def analyze_target(target_path: Path, config_path: Path) -> list:
    rules = load_analysis_config(config_path)
    python_files = collect_python_files(target_path)

    if not python_files:
        raise FileNotFoundError("No Python files found for analysis")

    findings = []

    for file_path in python_files:
        findings.extend(analyze_file(file_path, rules))

    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static analysis tool for detecting unsafe deserialization in Python code"
    )

    parser.add_argument(
        "target",
        help="Path to a Python file or project directory"
    )

    parser.add_argument(
        "-c",
        "--config",
        default="rules/config.yaml",
        help="Path to the YAML configuration file"
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output format"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Path to save the report"
    )

    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always return exit code 0, even if findings are detected"
    )

    return parser


def format_report(findings: list, output_format: str) -> str:
    if output_format == "json":
        return findings_to_json(findings)

    if output_format == "sarif":
        return findings_to_sarif(findings)

    return findings_to_console(findings)


def write_report(report: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        return

    print(report)


def main() -> None:
    parser = build_parser()

    try:
        args = parser.parse_args()

        findings = analyze_target(
            target_path=Path(args.target),
            config_path=Path(args.config),
        )

        report = format_report(
            findings=findings,
            output_format=args.format,
        )

        write_report(
            report=report,
            output_path=args.output,
        )

        if findings and not args.exit_zero:
            sys.exit(1)

        sys.exit(0)

    except Exception as error:
        print(f"Analysis error: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()