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

    # =========================
    # ANALYSIS ENTRYPOINT
    # =========================

    def analyze(self) -> list[Finding]:
        self.function_summaries = self.build_function_summaries()

        previous_tainted_variables: set[str] = set()

        for _ in range(len(self.assignment_nodes) + 1):
            self.apply_function_return_flows()

            propagated = self.data_flow_graph.propagate_taint(
                self.initial_tainted_variables
            )

            self.tainted_variables = propagated - self.safely_overwritten_variables

            if self.tainted_variables == previous_tainted_variables:
                break

            previous_tainted_variables = set(self.tainted_variables)

        self.check_direct_sink_calls()
        self.check_user_function_sink_calls()

        return self.findings

    # =========================
    # FUNCTION SUMMARIES
    # =========================

    def build_function_summaries(self) -> dict[str, FunctionSummary]:
        summaries = {}

        for name, node in self.function_definitions.items():
            summaries[name] = self.build_single_function_summary(node)

        return summaries

    def build_single_function_summary(self, function_node: ast.FunctionDef) -> FunctionSummary:
        summary = FunctionSummary()

        param_names = [arg.arg for arg in function_node.args.args]
        param_indexes = {name: i for i, name in enumerate(param_names)}

        local_deps = self.build_local_dependency_map(function_node)

        for node in ast.walk(function_node):
            # RETURN
            if isinstance(node, ast.Return) and node.value:
                if self.expression_contains_source(node.value):
                    summary.returns_tainted_source = True

                deps = self.extract_variable_dependencies(node.value)
                resolved = set()

                for d in deps:
                    resolved |= self.resolve_local_dependencies(d, local_deps)

                for p_name, p_idx in param_indexes.items():
                    if p_name in resolved:
                        summary.return_parameter_indexes.add(p_idx)

            # INTERNAL SINK
            if isinstance(node, ast.Call):
                func_name = self.resolve_qualified_name(node.func)

                if func_name not in self.get_sink_function_names():
                    continue

                for arg in node.args:
                    deps = self.extract_variable_dependencies(arg)
                    resolved = set()

                    for d in deps:
                        resolved |= self.resolve_local_dependencies(d, local_deps)

                    for p_name, p_idx in param_indexes.items():
                        if p_name in resolved:
                            summary.sink_parameter_indexes.setdefault(node, set()).add(p_idx)

        return summary

    # =========================
    # DATA FLOW INSIDE FUNCTIONS
    # =========================

    def build_local_dependency_map(self, function_node):
        deps = {}

        for node in ast.walk(function_node):
            if isinstance(node, ast.Assign):
                targets = self.extract_assignment_targets(node.targets)
                sources = self.extract_variable_dependencies(node.value)

                for t in targets:
                    deps.setdefault(t, set()).update(sources)

        return deps

    def resolve_local_dependencies(self, var, deps):
        visited = set()
        stack = [var]

        while stack:
            current = stack.pop()
            if current in visited:
                continue

            visited.add(current)

            for d in deps.get(current, set()):
                if d not in visited:
                    stack.append(d)

        return visited

    # =========================
    # INTERPROCEDURAL FLOW
    # =========================

    def apply_function_return_flows(self):
        for assign in self.assignment_nodes:
            if not isinstance(assign.value, ast.Call):
                continue

            fname = self.resolve_qualified_name(assign.value.func)

            if fname not in self.function_summaries:
                continue

            summary = self.function_summaries[fname]
            targets = self.extract_assignment_targets(assign.targets)

            for t in targets:
                if summary.returns_tainted_source:
                    self.initial_tainted_variables.add(t)
                    self.safely_overwritten_variables.discard(t)

                for idx in summary.return_parameter_indexes:
                    if idx >= len(assign.value.args):
                        continue

                    arg = assign.value.args[idx]

                    for dep in self.extract_variable_dependencies(arg):
                        self.data_flow_graph.add_dependency(dep, t)

                    self.safely_overwritten_variables.discard(t)

    # =========================
    # SINK CHECKING
    # =========================

    def check_direct_sink_calls(self):
        for call in self.detected_sink_calls:
            fname = self.resolve_qualified_name(call.func)

            if not fname:
                continue

            if self.has_safe_argument(fname, call):
                continue

            if self.has_tainted_argument(call):
                self.add_finding(call, fname)

    def check_user_function_sink_calls(self):
        for call in self.call_nodes:
            fname = self.resolve_qualified_name(call.func)

            if fname not in self.function_summaries:
                continue

            summary = self.function_summaries[fname]

            for sink_call, indexes in summary.sink_parameter_indexes.items():
                for idx in indexes:
                    if idx >= len(call.args):
                        continue

                    if self.is_tainted_expression(call.args[idx]):
                        sink_name = self.resolve_qualified_name(sink_call.func)
                        if sink_name:
                            self.add_interprocedural_finding(call, sink_name)

    # =========================
    # FINDINGS + TRACE
    # =========================

    def add_finding(self, call, resolved_name):
        trace = self.build_taint_trace(call)

        self.findings.append(
            Finding(
                file_path=self.source_file,
                line_number=getattr(call.func, "lineno", getattr(call, "lineno", 0)),
                function_name=self.get_source_call_name(call.func) or resolved_name,
                resolved_function_name=resolved_name,
                library_name=resolved_name.split(".")[0],
                description="Untrusted data is passed to a deserialization function",
                taint_trace=trace,
            )
        )

    def add_interprocedural_finding(self, call, resolved_name):
        trace = self.build_taint_trace(call)

        self.findings.append(
            Finding(
                file_path=self.source_file,
                line_number=getattr(call.func, "lineno", getattr(call, "lineno", 0)),
                function_name=self.get_source_call_name(call.func) or resolved_name,
                resolved_function_name=resolved_name,
                library_name=resolved_name.split(".")[0],
                description="Untrusted data is passed to a deserialization function",
                taint_trace=trace,
            )
        )

    def build_taint_trace(self, call):
        for arg in call.args:
            deps = self.extract_variable_dependencies(arg)

            for var in deps:
                if var in self.tainted_variables:
                    return self.data_flow_graph.get_taint_path(
                        source_variables=self.initial_tainted_variables,
                        target_variable=var
                    )
        return []

    # =========================
    # HELPERS
    # =========================

    def resolve_qualified_name(self, node):
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            base = self.resolve_qualified_name(node.value)
            if base:
                return f"{base}.{node.attr}"

        return None

    def get_source_call_name(self, node):
        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            base = self.get_source_call_name(node.value)
            if base:
                return f"{base}.{node.attr}"

        return None

    def has_tainted_argument(self, node):
        return any(self.is_tainted_expression(arg) for arg in node.args)

    def is_tainted_expression(self, node):


        if isinstance(node, ast.Subscript):
            return self.is_tainted_expression(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.is_tainted_expression(e) for e in node.elts)

        if isinstance(node, ast.Dict):
            return any(
                v is not None and self.is_tainted_expression(v)
                for v in node.values
            )

        if isinstance(node, ast.Call):
            fname = self.resolve_qualified_name(node.func)

            if fname in self.source_functions:
                return True

            if fname in self.propagation_functions:
                return any(self.is_tainted_expression(arg) for arg in node.args)

            if fname in self.function_summaries:
                summary = self.function_summaries[fname]

                if summary.returns_tainted_source:
                    return True

                for idx in summary.return_parameter_indexes:
                    if idx < len(node.args):
                        if self.is_tainted_expression(node.args[idx]):
                            return True

        if isinstance(node, ast.Attribute):
            attr = self.resolve_qualified_name(node)
            return attr in self.source_functions if attr else False

        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables

        return False

    def expression_contains_source(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                fname = self.resolve_qualified_name(child.func)
                if fname in self.source_functions:
                    return True

        return False

    def extract_assignment_targets(self, targets):
        result = set()
        for t in targets:
            if isinstance(t, ast.Name):
                result.add(t.id)
        return result

    def extract_variable_dependencies(self, node):
        result = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                result.add(child.id)
        return result

    def has_safe_argument(self, fname, node):
        safe_values = get_safe_argument_values(self.analysis_rules, fname)

        if not safe_values:
            return False

        for kw in node.keywords:
            val = self.resolve_qualified_name(kw.value)
            if val in safe_values:
                return True

        return False

    def get_sink_function_names(self):
        result = set()

        for sink in self.analysis_rules.get("sinks", []):
            module = sink.get("module")
            for method in sink.get("methods", []):
                result.add(f"{module}.{method}")

        return result