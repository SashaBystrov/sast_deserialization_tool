import ast
from pathlib import Path

from .config_loader import build_sink_function_set, get_safe_argument_values
from .data_flow import DataFlowGraph
from .models import Finding


class DeserializationAnalyzer(ast.NodeVisitor):
    """
    AST-based analyzer for detecting unsafe deserialization patterns.

    The analyzer performs three main steps:
    1. resolves imports and aliases;
    2. builds a data-flow graph and propagates taint labels;
    3. checks whether tainted data reaches deserialization sinks.
    """

    def __init__(self, source_file: str, analysis_rules: dict):
        self.source_file = source_file
        self.analysis_rules = analysis_rules

        self.source_functions = set(analysis_rules.get("sources", []))
        self.propagation_functions = set(analysis_rules.get("propagation_functions", []))
        self.sink_functions = build_sink_function_set(analysis_rules)

        self.import_aliases: dict[str, str] = {}

        self.initial_tainted_variables: set[str] = set()
        self.safely_overwritten_variables: set[str] = set()
        self.tainted_variables: set[str] = set()

        self.data_flow_graph = DataFlowGraph()

        self.detected_sink_calls: list[ast.Call] = []
        self.findings: list[Finding] = []

    def visit_Import(self, node: ast.Import) -> None:
        for imported_module in node.names:
            local_name = imported_module.asname or imported_module.name
            self.import_aliases[local_name] = imported_module.name

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module:
            self.generic_visit(node)
            return

        for imported_symbol in node.names:
            local_name = imported_symbol.asname or imported_symbol.name
            self.import_aliases[local_name] = f"{node.module}.{imported_symbol.name}"

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        target_variables = self.extract_assignment_targets(node.targets)
        dependency_variables = self.extract_variable_dependencies(node.value)

        is_source_value = self.is_source_expression(node.value)
        is_propagated_value = self.is_propagation_expression(node.value)

        for target_variable in target_variables:
            if is_source_value:
                self.initial_tainted_variables.add(target_variable)
                self.safely_overwritten_variables.discard(target_variable)

            elif dependency_variables or is_propagated_value:
                for dependency_variable in dependency_variables:
                    self.data_flow_graph.add_dependency(
                        source_variable=dependency_variable,
                        target_variable=target_variable,
                    )

                self.safely_overwritten_variables.discard(target_variable)

            else:
                self.safely_overwritten_variables.add(target_variable)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        function_name = self.resolve_qualified_name(node.func)

        if function_name in self.sink_functions:
            self.detected_sink_calls.append(node)

        self.generic_visit(node)

    def finalize_analysis(self) -> None:
        propagated_taint = self.data_flow_graph.propagate_taint(
            self.initial_tainted_variables
        )

        self.tainted_variables = propagated_taint - self.safely_overwritten_variables

        for sink_call in self.detected_sink_calls:
            function_name = self.resolve_qualified_name(sink_call.func)

            if not function_name:
                continue

            if self.has_safe_argument(function_name, sink_call):
                continue

            if self.has_tainted_argument(sink_call):
                self.findings.append(
                    Finding(
                        file_path=self.source_file,
                        line_number=getattr(sink_call, "lineno", 0),
                        function_name=function_name,
                        library_name=function_name.split(".")[0],
                        description="Untrusted data is passed to a deserialization function",
                    )
                )

    def extract_assignment_targets(self, targets: list[ast.expr]) -> set[str]:
        target_variables: set[str] = set()

        for target in targets:
            if isinstance(target, ast.Name):
                target_variables.add(target.id)

        return target_variables

    def extract_variable_dependencies(self, node: ast.AST) -> set[str]:
        dependency_variables: set[str] = set()

        for child_node in ast.walk(node):
            if isinstance(child_node, ast.Name):
                dependency_variables.add(child_node.id)

        return dependency_variables

    def resolve_qualified_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            base_name = self.resolve_qualified_name(node.value)

            if base_name:
                return f"{base_name}.{node.attr}"

        return None

    def is_source_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            function_name = self.resolve_qualified_name(node.func)
            return function_name in self.source_functions

        if isinstance(node, ast.Attribute):
            attribute_name = self.resolve_qualified_name(node)
            return attribute_name in self.source_functions if attribute_name else False

        return False

    def is_propagation_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            function_name = self.resolve_qualified_name(node.func)
            return function_name in self.propagation_functions

        return False

    def has_tainted_argument(self, node: ast.Call) -> bool:
        return any(
            self.is_tainted_expression(argument)
            for argument in node.args
        )

    def is_tainted_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables

        if isinstance(node, ast.Call):
            function_name = self.resolve_qualified_name(node.func)

            if function_name in self.source_functions:
                return True

            if function_name in self.propagation_functions:
                return any(
                    self.is_tainted_expression(argument)
                    for argument in node.args
                )

        if isinstance(node, ast.Attribute):
            attribute_name = self.resolve_qualified_name(node)
            return attribute_name in self.source_functions if attribute_name else False

        return False

    def has_safe_argument(self, function_name: str, node: ast.Call) -> bool:
        safe_arguments = get_safe_argument_values(self.analysis_rules, function_name)

        if not safe_arguments:
            return False

        for keyword_argument in node.keywords:
            resolved_value = self.resolve_qualified_name(keyword_argument.value)

            if resolved_value in safe_arguments:
                return True

        return False


def analyze_file(source_path: Path, analysis_rules: dict) -> list[Finding]:
    try:
        source_code = source_path.read_text(encoding="utf-8")
        syntax_tree = ast.parse(source_code)
    except SyntaxError:
        return []
    except UnicodeDecodeError:
        return []

    analyzer = DeserializationAnalyzer(
        source_file=str(source_path),
        analysis_rules=analysis_rules,
    )

    analyzer.visit(syntax_tree)
    analyzer.finalize_analysis()

    return analyzer.findings