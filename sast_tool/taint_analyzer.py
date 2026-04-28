import ast
from dataclasses import dataclass, field

from .config_loader import get_safe_argument_values
from .data_flow import DataFlowGraph
from .models import Finding


@dataclass
class FunctionSummary:
    returns_tainted_source: bool = False
    return_parameter_indexes: set[int] = field(default_factory=set)
    sink_parameter_indexes: dict[ast.Call, set[int]] = field(default_factory=dict)


class TaintAnalyzer:
    """
    Performs taint propagation and checks whether tainted data reaches
    unsafe deserialization functions.
    """

    def __init__(
        self,
        source_file: str,
        analysis_rules: dict,
        import_aliases: dict[str, str],
        data_flow_graph: DataFlowGraph,
        initial_tainted_variables: set[str],
        safely_overwritten_variables: set[str],
        detected_sink_calls: list[ast.Call],
        function_definitions: dict[str, ast.FunctionDef],
        assignment_nodes: list[ast.Assign],
        call_nodes: list[ast.Call],
    ):
        self.source_file = source_file
        self.analysis_rules = analysis_rules
        self.import_aliases = import_aliases
        self.data_flow_graph = data_flow_graph

        self.source_functions = set(analysis_rules.get("sources", []))
        self.propagation_functions = set(analysis_rules.get("propagation_functions", []))

        self.initial_tainted_variables = initial_tainted_variables
        self.safely_overwritten_variables = safely_overwritten_variables
        self.detected_sink_calls = detected_sink_calls

        self.function_definitions = function_definitions
        self.assignment_nodes = assignment_nodes
        self.call_nodes = call_nodes

        self.function_summaries: dict[str, FunctionSummary] = {}
        self.tainted_variables: set[str] = set()
        self.findings: list[Finding] = []

    def build_local_dependency_map(self, function_node: ast.FunctionDef) -> dict[str, set[str]]:
        local_dependencies: dict[str, set[str]] = {}

        for child_node in ast.walk(function_node):
            if not isinstance(child_node, ast.Assign):
                continue

            target_variables = self.extract_assignment_targets(child_node.targets)
            dependency_variables = self.extract_variable_dependencies(child_node.value)

            for target_variable in target_variables:
                local_dependencies.setdefault(target_variable, set()).update(dependency_variables)

        return local_dependencies

    def resolve_local_dependencies(
            self,
            variable_name: str,
            local_dependencies: dict[str, set[str]],
    ) -> set[str]:
        resolved_dependencies: set[str] = set()
        stack = [variable_name]

        while stack:
            current_variable = stack.pop()

            if current_variable in resolved_dependencies:
                continue

            resolved_dependencies.add(current_variable)

            for dependency in local_dependencies.get(current_variable, set()):
                if dependency not in resolved_dependencies:
                    stack.append(dependency)

        return resolved_dependencies
    def analyze(self) -> list[Finding]:
        self.function_summaries = self.build_function_summaries()
        self.apply_function_return_flows()

        propagated_taint = self.data_flow_graph.propagate_taint(
            self.initial_tainted_variables
        )

        self.tainted_variables = propagated_taint - self.safely_overwritten_variables

        self.check_direct_sink_calls()
        self.check_user_function_sink_calls()

        return self.findings

    def build_function_summaries(self) -> dict[str, FunctionSummary]:
        summaries: dict[str, FunctionSummary] = {}

        for function_name, function_node in self.function_definitions.items():
            summaries[function_name] = self.build_single_function_summary(function_node)

        return summaries

    def build_single_function_summary(self, function_node: ast.FunctionDef) -> FunctionSummary:
        summary = FunctionSummary()

        parameter_names = [
            argument.arg
            for argument in function_node.args.args
        ]

        parameter_indexes = {
            parameter_name: index
            for index, parameter_name in enumerate(parameter_names)
        }

        local_dependencies = self.build_local_dependency_map(function_node)

        for child_node in ast.walk(function_node):
            if isinstance(child_node, ast.Return) and child_node.value:
                if self.expression_contains_source(child_node.value):
                    summary.returns_tainted_source = True

                returned_variables = self.extract_variable_dependencies(child_node.value)
                resolved_return_dependencies: set[str] = set()

                for returned_variable in returned_variables:
                    resolved_return_dependencies.update(
                        self.resolve_local_dependencies(
                            variable_name=returned_variable,
                            local_dependencies=local_dependencies,
                        )
                    )

                for parameter_name, parameter_index in parameter_indexes.items():
                    if parameter_name in resolved_return_dependencies:
                        summary.return_parameter_indexes.add(parameter_index)

            if isinstance(child_node, ast.Call):
                function_name = self.resolve_qualified_name(child_node.func)

                if function_name not in self.get_sink_function_names():
                    continue

                for argument in child_node.args:
                    argument_dependencies = self.extract_variable_dependencies(argument)
                    resolved_argument_dependencies: set[str] = set()

                    for dependency in argument_dependencies:
                        resolved_argument_dependencies.update(
                            self.resolve_local_dependencies(
                                variable_name=dependency,
                                local_dependencies=local_dependencies,
                            )
                        )

                    for parameter_name, parameter_index in parameter_indexes.items():
                        if parameter_name in resolved_argument_dependencies:
                            summary.sink_parameter_indexes.setdefault(
                                child_node,
                                set(),
                            ).add(parameter_index)

        return summary

    def apply_function_return_flows(self) -> None:
        for assignment_node in self.assignment_nodes:
            if not isinstance(assignment_node.value, ast.Call):
                continue

            called_function_name = self.resolve_qualified_name(assignment_node.value.func)

            if called_function_name not in self.function_summaries:
                continue

            summary = self.function_summaries[called_function_name]
            target_variables = self.extract_assignment_targets(assignment_node.targets)

            for target_variable in target_variables:
                if summary.returns_tainted_source:
                    self.initial_tainted_variables.add(target_variable)
                    self.safely_overwritten_variables.discard(target_variable)

                for parameter_index in summary.return_parameter_indexes:
                    if parameter_index >= len(assignment_node.value.args):
                        continue

                    argument = assignment_node.value.args[parameter_index]

                    for dependency in self.extract_variable_dependencies(argument):
                        self.data_flow_graph.add_dependency(
                            source_variable=dependency,
                            target_variable=target_variable,
                        )

                    if self.is_tainted_expression(argument):
                        self.initial_tainted_variables.add(target_variable)
                        self.safely_overwritten_variables.discard(target_variable)

    def check_direct_sink_calls(self) -> None:
        for sink_call in self.detected_sink_calls:
            function_name = self.resolve_qualified_name(sink_call.func)

            if not function_name:
                continue

            if self.has_safe_argument(function_name, sink_call):
                continue

            if self.has_tainted_argument(sink_call):
                self.add_finding(sink_call, function_name)

    def check_user_function_sink_calls(self) -> None:
        for call_node in self.call_nodes:
            called_function_name = self.resolve_qualified_name(call_node.func)

            if called_function_name not in self.function_summaries:
                continue

            summary = self.function_summaries[called_function_name]

            for sink_call, parameter_indexes in summary.sink_parameter_indexes.items():
                for parameter_index in parameter_indexes:
                    if parameter_index >= len(call_node.args):
                        continue

                    if self.is_tainted_expression(call_node.args[parameter_index]):
                        sink_function_name = self.resolve_qualified_name(sink_call.func)

                        if sink_function_name:
                            self.add_interprocedural_finding(call_node, sink_function_name)

    def add_interprocedural_finding(
            self,
            call_node: ast.Call,
            resolved_sink_name: str,
    ) -> None:
        source_call_name = self.get_source_call_name(call_node.func)

        self.findings.append(
            Finding(
                file_path=self.source_file,
                line_number=getattr(
                    call_node.func,
                    "lineno",
                    getattr(call_node, "lineno", 0),
                ),
                function_name=source_call_name or resolved_sink_name,
                resolved_function_name=resolved_sink_name,
                library_name=resolved_sink_name.split(".")[0],
                description="Untrusted data is passed to a deserialization function",
            )
        )

    def add_finding(self, sink_call: ast.Call, resolved_function_name: str) -> None:
        source_call_name = self.get_source_call_name(sink_call.func)

        self.findings.append(
            Finding(
                file_path=self.source_file,
                line_number=getattr(
                    sink_call.func,
                    "lineno",
                    getattr(sink_call, "lineno", 0),
                ),
                function_name=source_call_name or resolved_function_name,
                resolved_function_name=resolved_function_name,
                library_name=resolved_function_name.split(".")[0],
                description="Untrusted data is passed to a deserialization function",
            )
        )

    def get_sink_function_names(self) -> set[str]:
        sink_functions = set()

        for sink_definition in self.analysis_rules.get("sinks", []):
            module_name = sink_definition.get("module")

            for method_name in sink_definition.get("methods", []):
                sink_functions.add(f"{module_name}.{method_name}")

        return sink_functions

    def resolve_qualified_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            base_name = self.resolve_qualified_name(node.value)

            if base_name:
                return f"{base_name}.{node.attr}"

        return None

    def get_source_call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            base_name = self.get_source_call_name(node.value)

            if base_name:
                return f"{base_name}.{node.attr}"

        return None

    def has_tainted_argument(self, node: ast.Call) -> bool:
        return any(
            self.is_tainted_expression(argument)
            for argument in node.args
        )

    def is_tainted_expression(self, node) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables

        if isinstance(node, ast.Subscript):
            return self.is_tainted_expression(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(
                self.is_tainted_expression(element)
                for element in node.elts
            )

        if isinstance(node, ast.Dict):
            return any(
                value is not None and self.is_tainted_expression(value)
                for value in node.values
            )

        if isinstance(node, ast.Call):
            function_name = self.resolve_qualified_name(node.func)

            if function_name in self.source_functions:
                return True

            if function_name in self.propagation_functions:
                return any(
                    self.is_tainted_expression(argument)
                    for argument in node.args
                )

            if function_name in self.function_summaries:
                summary = self.function_summaries[function_name]

                if summary.returns_tainted_source:
                    return True

                for parameter_index in summary.return_parameter_indexes:
                    if parameter_index < len(node.args):
                        if self.is_tainted_expression(node.args[parameter_index]):
                            return True

        if isinstance(node, ast.Attribute):
            attribute_name = self.resolve_qualified_name(node)
            return attribute_name in self.source_functions if attribute_name else False

        return False

    def expression_contains_source(self, node: ast.AST) -> bool:
        for child_node in ast.walk(node):
            if isinstance(child_node, ast.Call):
                function_name = self.resolve_qualified_name(child_node.func)

                if function_name in self.source_functions:
                    return True

            if isinstance(child_node, ast.Attribute):
                attribute_name = self.resolve_qualified_name(child_node)

                if attribute_name in self.source_functions:
                    return True

        return False

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

    def has_safe_argument(self, function_name: str, node: ast.Call) -> bool:
        safe_argument_values = get_safe_argument_values(
            self.analysis_rules,
            function_name,
        )

        if not safe_argument_values:
            return False

        for keyword_argument in node.keywords:
            resolved_value = self.resolve_qualified_name(keyword_argument.value)

            if resolved_value in safe_argument_values:
                return True

        return False