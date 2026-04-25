from dataclasses import dataclass, field


@dataclass
class DataFlowGraph:
    edges: dict[str, set[str]] = field(default_factory=dict)

    def add_edge(self, source: str, target: str) -> None:
        if source not in self.edges:
            self.edges[source] = set()
        self.edges[source].add(target)

    def propagate_taint(self, initial_tainted: set[str]) -> set[str]:
        tainted = set(initial_tainted)
        changed = True

        while changed:
            changed = False

            for source, targets in self.edges.items():
                if source in tainted:
                    for target in targets:
                        if target not in tainted:
                            tainted.add(target)
                            changed = True

        return tainted