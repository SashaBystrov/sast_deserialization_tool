import ast
from pathlib import Path

from .models import Finding
from .config_loader import build_sink_set, get_safe_arguments
from .data_flow import DataFlowGraph


class DeserializationAnalyzer(ast.NodeVisitor):
    def __init__(self, filename: str, rules: dict):
        self.filename = filename
        self.rules = rules

        self.sources = set(rules.get("sources", []))
        self.propagation_functions = set(rules.get("propagation_functions", []))
        self.sinks = build_sink_set(rules)

        self.import_aliases: dict[str, str] = {}
        self.initial_tainted_vars: set[str] = set()
        self.safe_overwritten_vars: set[str] = set()
        self.tainted_vars: set[str] = set()

        self.data_flow_graph = DataFlowGraph()
        self.sink_calls: list[ast.Call] = []
        self.findings: list[Finding] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.import_aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                local_name = alias.asname or alias.name
                self.import_aliases[local_name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        target_names = self.extract_target_names(node.targets)
        source_names = self.extract_variable_dependencies(node.value)

        value_is_tainted_source = self.is_source_expression(node.value)
        value_is_propagation = self.is_propagation_expression(node.value)

        for target in target_names:
            if value_is_tainted_source:
                self.initial_tainted_vars.add(target)
                self.safe_overwritten_vars.discard(target)

            elif source_names or value_is_propagation:
                for source in source_names:
                    self.data_flow_graph.add_edge(source, target)

                self.safe_overwritten_vars.discard(target)

            else:
                # Безопасная перезапись: константа, литерал, внутреннее значение.
                self.safe_overwritten_vars.add(target)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        function_name = self.resolve_name(node.func)

        if function_name in self.sinks:
            self.sink_calls.append(node)

        self.generic_visit(node)

    def finalize_analysis(self) -> None:
        propagated = self.data_flow_graph.propagate_taint(self.initial_tainted_vars)
        self.tainted_vars = propagated - self.safe_overwritten_vars

        for node in self.sink_calls:
            function_name = self.resolve_name(node.func)

            if not function_name:
                continue

            if self.has_safe_argument(function_name, node):
                continue

            if self.has_tainted_argument(node):
                self.findings.append(
                    Finding(
                        file=self.filename,
                        line=getattr(node, "lineno", 0),
                        function=function_name,
                        library=function_name.split(".")[0],
                        description="Передача недоверенных данных в функцию десериализации",
                    )
                )

    def extract_target_names(self, targets: list[ast.expr]) -> set[str]:
        names = set()

        for target in targets:
            if isinstance(target, ast.Name):
                names.add(target.id)

        return names

    def extract_variable_dependencies(self, node: ast.AST) -> set[str]:
        dependencies = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                dependencies.add(child.id)

        return dependencies

    def resolve_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            base = self.resolve_name(node.value)
            if base:
                return f"{base}.{node.attr}"

        return None

    def is_source_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            function_name = self.resolve_name(node.func)
            return function_name in self.sources

        if isinstance(node, ast.Attribute):
            full_name = self.resolve_name(node)
            return full_name in self.sources if full_name else False

        return False

    def is_propagation_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            function_name = self.resolve_name(node.func)
            return function_name in self.propagation_functions

        return False

    def has_tainted_argument(self, node: ast.Call) -> bool:
        return any(self.is_tainted_expression(argument) for argument in node.args)

    def is_tainted_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars

        if isinstance(node, ast.Call):
            function_name = self.resolve_name(node.func)

            if function_name in self.sources:
                return True

            if function_name in self.propagation_functions:
                return any(self.is_tainted_expression(arg) for arg in node.args)

        if isinstance(node, ast.Attribute):
            full_name = self.resolve_name(node)
            return full_name in self.sources if full_name else False

        return False

    def has_safe_argument(self, function_name: str, node: ast.Call) -> bool:
        safe_arguments = get_safe_arguments(self.rules, function_name)

        if not safe_arguments:
            return False

        for keyword in node.keywords:
            resolved_value = self.resolve_name(keyword.value)

            if resolved_value in safe_arguments:
                return True

        return False


def analyze_file(path: Path, rules: dict) -> list[Finding]:
    try:
        source_code = path.read_text(encoding="utf-8")
        tree = ast.parse(source_code)
    except SyntaxError:
        return []
    except UnicodeDecodeError:
        return []

    analyzer = DeserializationAnalyzer(str(path), rules)
    analyzer.visit(tree)
    analyzer.finalize_analysis()

    return analyzer.findings