import ast

from .config_loader import build_sink_function_set
from .data_flow import DataFlowGraph


class DeserializationASTAnalyzer(ast.NodeVisitor):
    """
    Collects structural information from AST:
    imports, data dependencies and deserialization sink calls.
    """

    def __init__(self, analysis_rules: dict):
        self.analysis_rules = analysis_rules

        self.source_functions = set(analysis_rules.get("sources", []))
        self.propagation_functions = set(analysis_rules.get("propagation_functions", []))
        self.sink_functions = build_sink_function_set(analysis_rules)

        self.import_aliases: dict[str, str] = {}
        self.initial_tainted_variables: set[str] = set()
        self.safely_overwritten_variables: set[str] = set()

        self.data_flow_graph = DataFlowGraph()
        self.detected_sink_calls: list[ast.Call] = []

        self.function_definitions: dict[str, ast.FunctionDef] = {}
        self.assignment_nodes: list[ast.Assign] = []
        self.call_nodes: list[ast.Call] = []

        self.conditional_depth = 0

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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_definitions[node.name] = node
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.conditional_depth += 1

        for statement in node.body:
            self.visit(statement)

        for statement in node.orelse:
            self.visit(statement)

        self.conditional_depth -= 1

    def visit_Assign(self, node: ast.Assign) -> None:
        self.assignment_nodes.append(node)
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
                if self.conditional_depth == 0:
                    self.safely_overwritten_variables.add(target_variable)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.call_nodes.append(node)
        function_name = self.resolve_qualified_name(node.func)

        if function_name in self.sink_functions:
            self.detected_sink_calls.append(node)

        self.generic_visit(node)

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