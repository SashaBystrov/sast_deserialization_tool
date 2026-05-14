from dataclasses import dataclass, asdict, field


@dataclass
class Finding:
    file_path: str
    line_number: int
    function_name: str
    resolved_function_name: str
    library_name: str
    description: str

    # Добавляем новое поле для трассировки (по умолчанию пустой список)
    taint_trace: list[str] = field(default_factory=list)

    severity: str = "HIGH"
    rule_id: str = "sast.python.unsafe_deserialization"

    def to_dict(self) -> dict:
        return asdict(self)