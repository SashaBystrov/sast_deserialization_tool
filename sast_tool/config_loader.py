from pathlib import Path

import yaml


REQUIRED_RULE_SECTIONS = {"sources", "propagation_functions", "sinks"}


def load_analysis_config(config_path: str | Path) -> dict:
    """
    Load and validate analysis rules from a YAML configuration file.
    """

    config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as config_file:
        config_data = yaml.safe_load(config_file)

    if not isinstance(config_data, dict):
        raise ValueError("Configuration file must contain a dictionary")

    rules = config_data.get("rules")

    if not isinstance(rules, dict):
        raise ValueError("Configuration must contain a 'rules' dictionary")

    missing_sections = REQUIRED_RULE_SECTIONS - set(rules.keys())

    if missing_sections:
        missing = ", ".join(sorted(missing_sections))
        raise ValueError(f"Missing required rule sections: {missing}")

    return rules


def build_sink_function_set(rules: dict) -> set[str]:
    """
    Convert sink definitions into fully qualified function names.
    """

    sink_functions: set[str] = set()

    for sink in rules.get("sinks", []):
        module_name = sink.get("module")
        method_names = sink.get("methods", [])

        if not module_name:
            continue

        for method_name in method_names:
            sink_functions.add(f"{module_name}.{method_name}")

    return sink_functions


def get_safe_argument_values(rules: dict, function_name: str) -> set[str]:
    """
    Return safe argument values configured for a given sink function.
    """

    safe_values: set[str] = set()

    for sink in rules.get("sinks", []):
        module_name = sink.get("module")
        method_names = sink.get("methods", [])

        for method_name in method_names:
            qualified_name = f"{module_name}.{method_name}"

            if qualified_name == function_name:
                safe_values.update(sink.get("safe_arguments", []))

    return safe_values