from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    function: str
    library: str
    description: str