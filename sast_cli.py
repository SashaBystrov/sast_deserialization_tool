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


def collect_python_source_files(target_path: Path) -> list[Path]:
    if target_path.is_file() and target_path.suffix == ".py":
        return [target_path]

    if target_path.is_dir():
        return list(target_path.rglob("*.py"))

    return []


def analyze_target(target_path: Path, config_path: Path) -> list:
    analysis_rules = load_analysis_config(config_path)
    python_files = collect_python_source_files(target_path)

    if not python_files:
        raise FileNotFoundError("No Python source files found for analysis")

    analysis_findings = []

    for source_file_path in python_files:
        analysis_findings.extend(
            analyze_file(source_file_path, analysis_rules)
        )

    return analysis_findings


def build_argument_parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Static analysis tool for detecting unsafe deserialization in Python code"
    )

    argument_parser.add_argument(
        "target",
        help="Path to a Python file or project directory"
    )

    argument_parser.add_argument(
        "-c",
        "--config",
        default="rules/config.yaml",
        help="Path to the YAML configuration file with analysis rules"
    )

    argument_parser.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output format"
    )

    argument_parser.add_argument(
        "-o",
        "--output",
        help="Path to save the analysis report"
    )

    argument_parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always return exit code 0, even if vulnerabilities are found"
    )

    return argument_parser


def format_analysis_report(findings: list, output_format: str) -> str:
    if output_format == "json":
        return findings_to_json(findings)

    if output_format == "sarif":
        return findings_to_sarif(findings)

    return findings_to_console(findings)


def write_or_print_report(report_content: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(report_content, encoding="utf-8")
        return

    print(report_content)


def main() -> None:
    argument_parser = build_argument_parser()

    try:
        cli_arguments = argument_parser.parse_args()

        analysis_findings = analyze_target(
            target_path=Path(cli_arguments.target),
            config_path=Path(cli_arguments.config),
        )

        report_content = format_analysis_report(
            findings=analysis_findings,
            output_format=cli_arguments.format,
        )

        write_or_print_report(
            report_content=report_content,
            output_path=cli_arguments.output,
        )

        if analysis_findings and not cli_arguments.exit_zero:
            sys.exit(1)

        sys.exit(0)

    except Exception as error:
        print(f"Analysis error: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()