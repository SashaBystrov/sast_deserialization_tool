"""
SAST tool for detecting unsafe deserialization vulnerabilities in Python code.
"""

from .analyzer import analyze_file
from .config_loader import load_analysis_config
from .models import Finding
from .reporter import (
    findings_to_console,
    findings_to_json,
    findings_to_sarif,
)

__all__ = [
    "analyze_file",
    "load_analysis_config",
    "Finding",
    "findings_to_console",
    "findings_to_json",
    "findings_to_sarif",
]

__version__ = "1.0.0"
__author__ = "A. A. Bystrov"