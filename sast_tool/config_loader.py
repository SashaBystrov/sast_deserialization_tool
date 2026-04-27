from pathlib import Path
import yaml


REQUIRED_RULE_SECTIONS = {"sources", "propagation_functions", "sinks"}


def load_analysis_config(config_path: str | Path) -> dict:
    """
    Load and validate YAML configuration for the SAST tool.
    """

    config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as config_file:
        config_data = yaml.safe_load(config_file)

    if not isinstance(config_data, dict) or "rules" not in config_data:
        raise ValueError("Configuration must contain a top-level 'rules' section")

    rules = config_data["rules"]

    if not isinstance(rules, dict):
        raise ValueError("The 'rules' section must be a dictionary")

    missing_sections = REQUIRED_RULE_SECTIONS - set(rules.keys())
    if missing_sections:
        raise ValueError(
            f"Missing required rule sections: {', '.join(sorted(missing_sections))}"
        )

    return rules


def build_sink_function_set(analysis_rules: dict) -> set[str]:
    """
    Convert sink definitions into a set of fully qualified function names.
    Example: 'pickle.loads'
    """

    sink_functions: set[str] = set()

    for sink_definition in analysis_rules.get("sinks", []):
        module_name = sink_definition["module"]

        for method_name in sink_definition.get("methods", []):
            sink_functions.add(f"{module_name}.{method_name}")

    return sink_functions


def get_safe_argument_values(analysis_rules: dict, function_name: str) -> set[str]:
    """
    Retrieve safe argument values for a specific sink function.
    Example: yaml.SafeLoader
    """

    safe_values: set[str] = set()

    for sink_definition in analysis_rules.get("sinks", []):
        module_name = sink_definition.get("module")
        methods = sink_definition.get("methods", [])

        for method_name in methods:
            qualified_name = f"{module_name}.{method_name}"

            if qualified_name == function_name:
                safe_values.update(sink_definition.get("safe_arguments", []))

    return safe_values