from dataclasses import dataclass, field


@dataclass
class DataFlowGraph:
    """
    Directed graph used to represent data dependencies between variables.

    Each edge has the form:
        source_variable -> target_variable

    This means that the value of the target variable depends on the value of
    the source variable.
    """

    adjacency_list: dict[str, set[str]] = field(default_factory=dict)

    def add_dependency(self, source_variable: str, target_variable: str) -> None:
        """
        Add a data dependency between two variables.
        """

        self.adjacency_list.setdefault(source_variable, set()).add(target_variable)

    def propagate_taint(self, initially_tainted_variables: set[str]) -> set[str]:
        """
        Propagate taint labels through the data-flow graph until a fixed point
        is reached.
        """

        tainted_variables = set(initially_tainted_variables)
        has_changes = True

        while has_changes:
            has_changes = False

            for source_variable, target_variables in self.adjacency_list.items():
                if source_variable not in tainted_variables:
                    continue

                for target_variable in target_variables:
                    if target_variable not in tainted_variables:
                        tainted_variables.add(target_variable)
                        has_changes = True

        return tainted_variables