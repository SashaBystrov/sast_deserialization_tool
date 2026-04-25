from pathlib import Path
import yaml


REQUIRED_RULE_SECTIONS = {"sources", "propagation_functions", "sinks"}


def load_config(path: str | Path) -> dict:
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(f"Конфигурационный файл не найден: {config_path}")

    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError("Конфигурационный файл должен содержать раздел 'rules'")

    rules = data["rules"]

    if not isinstance(rules, dict):
        raise ValueError("Раздел 'rules' должен быть словарём")

    missing_sections = REQUIRED_RULE_SECTIONS - set(rules.keys())
    if missing_sections:
        raise ValueError(f"В конфигурации отсутствуют разделы: {missing_sections}")

    return rules


def build_sink_set(rules: dict) -> set[str]:
    sinks = set()

    for sink in rules.get("sinks", []):
        module = sink["module"]
        for method in sink.get("methods", []):
            sinks.add(f"{module}.{method}")

    return sinks


def get_safe_arguments(rules: dict, function_name: str) -> set[str]:
    safe_arguments = set()

    for sink in rules.get("sinks", []):
        module = sink.get("module")
        methods = sink.get("methods", [])

        for method in methods:
            if f"{module}.{method}" == function_name:
                safe_arguments.update(sink.get("safe_arguments", []))

    return safe_arguments