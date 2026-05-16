import ast
from pathlib import Path

from .ast_analyzer import DeserializationASTAnalyzer
from .models import Finding
from .taint_analyzer import TaintAnalyzer


def analyze_file(file_path: Path, rules: dict) -> list[Finding]:
    try:
        source_code = file_path.read_text(encoding="utf-8")
        syntax_tree = ast.parse(source_code)
    except (SyntaxError, UnicodeDecodeError):
        return []

    ast_analyzer = DeserializationASTAnalyzer(rules)
    ast_analyzer.visit(syntax_tree)

    taint_analyzer = TaintAnalyzer(
        source_file=str(file_path),
        rules=rules,
        import_aliases=ast_analyzer.import_aliases,
        data_flow_graph=ast_analyzer.data_flow_graph,
        initial_tainted_variables=ast_analyzer.initial_tainted_variables,
        safely_overwritten_variables=ast_analyzer.safely_overwritten_variables,
        sink_calls=ast_analyzer.sink_calls,
        function_definitions=ast_analyzer.function_definitions,
        assignment_nodes=ast_analyzer.assignment_nodes,
        call_nodes=ast_analyzer.call_nodes,
    )

    return taint_analyzer.analyze()