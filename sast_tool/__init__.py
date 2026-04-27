"""
SAST tool for detecting unsafe deserialization vulnerabilities in Python code.

This package provides functionality for:
- static analysis of Python source code;
- taint-based data flow analysis;
- detection of unsafe deserialization patterns;
- generation of reports in multiple formats (console, JSON, SARIF).
"""

from .analyzer import analyze_file
from .config_loader import load_analysis_config
from .reporter import (
    findings_to_console,
    findings_to_json,
    findings_to_sarif,
)
from .models import Finding

__all__ = [
    "analyze_file",
    "load_analysis_config",
    "findings_to_console",
    "findings_to_json",
    "findings_to_sarif",
    "Finding",
]

__version__ = "1.0.0"
__author__ = "A.A. Bystrov"