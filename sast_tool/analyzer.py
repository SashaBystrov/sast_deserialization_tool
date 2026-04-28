import ast
from pathlib import Path

from .ast_analyzer import DeserializationASTAnalyzer
from .models import Finding
from .taint_analyzer import TaintAnalyzer


def analyze_file(source_path: Path, analysis_rules: dict) -> list[Finding]:
    try:
        source_code = source_path.read_text(encoding="utf-8")
        syntax_tree = ast.parse(source_code)
    except SyntaxError:
        return []
    except UnicodeDecodeError:
        return []

    ast_analyzer = DeserializationASTAnalyzer(analysis_rules)
    ast_analyzer.visit(syntax_tree)

    taint_analyzer = TaintAnalyzer(
        source_file=str(source_path),
        analysis_rules=analysis_rules,
        import_aliases=ast_analyzer.import_aliases,
        data_flow_graph=ast_analyzer.data_flow_graph,
        initial_tainted_variables=ast_analyzer.initial_tainted_variables,
        safely_overwritten_variables=ast_analyzer.safely_overwritten_variables,
        detected_sink_calls=ast_analyzer.detected_sink_calls,
        function_definitions=ast_analyzer.function_definitions,
        assignment_nodes=ast_analyzer.assignment_nodes,
        call_nodes=ast_analyzer.call_nodes,
    )

    return taint_analyzer.analyze()