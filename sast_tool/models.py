from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    """
    Represents a detected unsafe deserialization issue.
    """

    file_path: str
    line_number: int
    function_name: str
    resolved_function_name: str
    library_name: str
    description: str
    severity: str = "HIGH"
    rule_id: str = "sast.python.unsafe_deserialization"
    taint_trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)