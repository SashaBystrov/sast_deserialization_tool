import ast
from dataclasses import dataclass, field

from .config_loader import get_safe_argument_values
from .data_flow import DataFlowGraph
from .models import Finding


@dataclass
class FunctionSummary:
    returns_source: bool = False
    return_parameter_indexes: set[int] = field(default_factory=set)
    sink_parameter_indexes: dict[ast.Call, set[int]] = field(default_factory=dict)


class TaintAnalyzer:
    def __init__(
        self,
        source_file: str,
        rules: dict,
        import_aliases: dict[str, str],
        data_flow_graph: DataFlowGraph,
        initial_tainted_variables: set[str],
        safely_overwritten_variables: set[str],
        sink_calls: list[ast.Call],
        function_definitions: dict[str, ast.FunctionDef],
        assignment_nodes: list[ast.Assign],
        call_nodes: list[ast.Call],
    ):
        self.source_file = source_file
        self.rules = rules
        self.import_aliases = import_aliases
        self.data_flow_graph = data_flow_graph

        self.source_functions = set(rules.get("sources", []))
        self.propagation_functions = set(rules.get("propagation_functions", []))

        self.initial_tainted_variables = initial_tainted_variables
        self.safely_overwritten_variables = safely_overwritten_variables
        self.sink_calls = sink_calls

        self.function_definitions = function_definitions
        self.assignment_nodes = assignment_nodes
        self.call_nodes = call_nodes

        self.function_summaries: dict[str, FunctionSummary] = {}
        self.tainted_variables: set[str] = set()
        self.findings: list[Finding] = []

    def analyze(self) -> list[Finding]:
        self.function_summaries = self.build_function_summaries()
        self.apply_function_return_flows()

        self.tainted_variables = (
            self.data_flow_graph.propagate_taint(self.initial_tainted_variables)
            - self.safely_overwritten_variables
        )

        self.check_direct_sink_calls()
        self.check_user_function_sink_calls()

        return self.findings

    def build_function_summaries(self) -> dict[str, FunctionSummary]:
        summaries: dict[str, FunctionSummary] = {}

        for function_name, function_node in self.function_definitions.items():
            summaries[function_name] = self.build_function_summary(function_node)

        return summaries

    def build_function_summary(self, function_node: ast.FunctionDef) -> FunctionSummary:
        summary = FunctionSummary()
        parameter_indexes = {
            argument.arg: index
            for index, argument in enumerate(function_node.args.args)
        }

        local_dependencies = self.build_local_dependency_map(function_node)

        for node in ast.walk(function_node):
            if isinstance(node, ast.Return) and node.value:
                self.update_return_summary(
                    summary=summary,
                    return_node=node,
                    parameter_indexes=parameter_indexes,
                    local_dependencies=local_dependencies,
                )

            if isinstance(node, ast.Call):
                self.update_sink_summary(
                    summary=summary,
                    call_node=node,
                    parameter_indexes=parameter_indexes,
                    local_dependencies=local_dependencies,
                )

        return summary

    def update_return_summary(
        self,
        summary: FunctionSummary,
        return_node: ast.Return,
        parameter_indexes: dict[str, int],
        local_dependencies: dict[str, set[str]],
    ) -> None:
        if self.expression_contains_source(return_node.value):
            summary.returns_source = True

        dependencies = self.resolve_expression_dependencies(
            return_node.value,
            local_dependencies,
        )

        for parameter_name, parameter_index in parameter_indexes.items():
            if parameter_name in dependencies:
                summary.return_parameter_indexes.add(parameter_index)

    def update_sink_summary(
        self,
        summary: FunctionSummary,
        call_node: ast.Call,
        parameter_indexes: dict[str, int],
        local_dependencies: dict[str, set[str]],
    ) -> None:
        function_name = self.resolve_qualified_name(call_node.func)

        if function_name not in self.get_sink_function_names():
            return

        for argument in call_node.args:
            dependencies = self.resolve_expression_dependencies(
                argument,
                local_dependencies,
            )

            for parameter_name, parameter_index in parameter_indexes.items():
                if parameter_name in dependencies:
                    summary.sink_parameter_indexes.setdefault(
                        call_node,
                        set(),
                    ).add(parameter_index)

    def build_local_dependency_map(
        self,
        function_node: ast.FunctionDef,
    ) -> dict[str, set[str]]:
        dependencies: dict[str, set[str]] = {}

        for node in ast.walk(function_node):
            if not isinstance(node, ast.Assign):
                continue

            targets = self.extract_assignment_targets(node.targets)
            sources = self.extract_variable_dependencies(node.value)

            for target in targets:
                dependencies.setdefault(target, set()).update(sources)

        return dependencies

    def resolve_expression_dependencies(
        self,
        node: ast.AST,
        local_dependencies: dict[str, set[str]],
    ) -> set[str]:
        resolved_dependencies: set[str] = set()

        for variable in self.extract_variable_dependencies(node):
            resolved_dependencies.update(
                self.resolve_local_dependencies(variable, local_dependencies)
            )

        return resolved_dependencies

    def resolve_local_dependencies(
        self,
        variable: str,
        local_dependencies: dict[str, set[str]],
    ) -> set[str]:
        resolved: set[str] = set()
        stack = [variable]

        while stack:
            current = stack.pop()

            if current in resolved:
                continue

            resolved.add(current)

            for dependency in local_dependencies.get(current, set()):
                stack.append(dependency)

        return resolved

    def apply_function_return_flows(self) -> None:
        for assignment in self.assignment_nodes:
            if not isinstance(assignment.value, ast.Call):
                continue

            function_name = self.resolve_qualified_name(assignment.value.func)

            if function_name not in self.function_summaries:
                continue

            summary = self.function_summaries[function_name]
            targets = self.extract_assignment_targets(assignment.targets)

            for target in targets:
                if summary.returns_source:
                    self.initial_tainted_variables.add(target)
                    self.safely_overwritten_variables.discard(target)

                for parameter_index in summary.return_parameter_indexes:
                    if parameter_index >= len(assignment.value.args):
                        continue

                    argument = assignment.value.args[parameter_index]

                    for dependency in self.extract_variable_dependencies(argument):
                        self.data_flow_graph.add_dependency(
                            source_variable=dependency,
                            target_variable=target,
                        )

                    self.safely_overwritten_variables.discard(target)

    def check_direct_sink_calls(self) -> None:
        for sink_call in self.sink_calls:
            function_name = self.resolve_qualified_name(sink_call.func)

            if not function_name:
                continue

            if self.has_safe_argument(function_name, sink_call):
                continue

            if self.has_tainted_argument(sink_call):
                self.add_finding(sink_call, function_name)

    def check_user_function_sink_calls(self) -> None:
        for call in self.call_nodes:
            function_name = self.resolve_qualified_name(call.func)

            if function_name not in self.function_summaries:
                continue

            summary = self.function_summaries[function_name]

            for sink_call, parameter_indexes in summary.sink_parameter_indexes.items():
                for parameter_index in parameter_indexes:
                    if parameter_index >= len(call.args):
                        continue

                    if self.is_tainted_expression(call.args[parameter_index]):
                        sink_name = self.resolve_qualified_name(sink_call.func)

                        if sink_name:
                            self.add_interprocedural_finding(call, sink_name)

    def add_finding(self, call: ast.Call, resolved_function_name: str) -> None:
        self.findings.append(
            Finding(
                file_path=self.source_file,
                line_number=getattr(call.func, "lineno", getattr(call, "lineno", 0)),
                function_name=self.get_source_call_name(call.func) or resolved_function_name,
                resolved_function_name=resolved_function_name,
                library_name=resolved_function_name.split(".")[0],
                description="Untrusted data is passed to a deserialization function",
                taint_trace=self.build_taint_trace(call),
            )
        )

    def add_interprocedural_finding(
        self,
        call: ast.Call,
        resolved_function_name: str,
    ) -> None:
        self.findings.append(
            Finding(
                file_path=self.source_file,
                line_number=getattr(call.func, "lineno", getattr(call, "lineno", 0)),
                function_name=self.get_source_call_name(call.func) or resolved_function_name,
                resolved_function_name=resolved_function_name,
                library_name=resolved_function_name.split(".")[0],
                description="Untrusted data is passed to a deserialization function",
                taint_trace=self.build_taint_trace(call),
            )
        )

    def build_taint_trace(self, call: ast.Call) -> list[str]:
        for argument in call.args:
            for variable in self.extract_variable_dependencies(argument):
                if variable in self.tainted_variables:
                    for source in self.initial_tainted_variables:
                        path = self.data_flow_graph.get_taint_path(
                            source_variable=source,
                            target_variable=variable,
                        )

                        if path:
                            return path

        return []

    def has_tainted_argument(self, call: ast.Call) -> bool:
        return any(
            self.is_tainted_expression(argument)
            for argument in call.args
        )

    def is_tainted_expression(self, node: ast.AST) -> bool:
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

                if summary.returns_source:
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
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                function_name = self.resolve_qualified_name(child.func)

                if function_name in self.source_functions:
                    return True

            if isinstance(child, ast.Attribute):
                attribute_name = self.resolve_qualified_name(child)

                if attribute_name in self.source_functions:
                    return True

        return False

    def has_safe_argument(self, function_name: str, call: ast.Call) -> bool:
        safe_values = get_safe_argument_values(self.rules, function_name)

        if not safe_values:
            return False

        for keyword in call.keywords:
            value_name = self.resolve_qualified_name(keyword.value)

            if value_name in safe_values:
                return True

        return False

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

    def extract_assignment_targets(self, targets: list[ast.expr]) -> set[str]:
        result: set[str] = set()

        for target in targets:
            if isinstance(target, ast.Name):
                result.add(target.id)

        return result

    def extract_variable_dependencies(self, node: ast.AST) -> set[str]:
        result: set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                result.add(child.id)

        return result

    def get_sink_function_names(self) -> set[str]:
        result: set[str] = set()

        for sink in self.rules.get("sinks", []):
            module_name = sink.get("module")

            for method_name in sink.get("methods", []):
                result.add(f"{module_name}.{method_name}")

        return result