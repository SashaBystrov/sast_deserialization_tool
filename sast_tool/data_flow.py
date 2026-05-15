from collections import deque


class DataFlowGraph:
    """
    Directed graph representing variable data dependencies.

    Example:
        a = input()
        b = a
        c = b

    Graph:
        a -> b -> c
    """

    def __init__(self) -> None:
        self.adjacency_list: dict[str, set[str]] = {}

    def add_dependency(self, source_variable: str, target_variable: str) -> None:
        """
        Register a dependency between two variables.
        """

        self.adjacency_list.setdefault(
            source_variable,
            set(),
        ).add(target_variable)

    def propagate_taint(
        self,
        initial_tainted_variables: set[str],
    ) -> set[str]:
        """
        Propagate taint labels through the graph until a fixed point is reached.
        """

        tainted_variables = set(initial_tainted_variables)
        queue = deque(initial_tainted_variables)

        while queue:
            current_variable = queue.popleft()

            for dependent_variable in self.adjacency_list.get(current_variable, set()):
                if dependent_variable in tainted_variables:
                    continue

                tainted_variables.add(dependent_variable)
                queue.append(dependent_variable)

        return tainted_variables

    def get_taint_path(
        self,
        source_variable: str,
        target_variable: str,
    ) -> list[str]:
        """
        Return one dependency path between source and target variables.
        """

        queue = deque([(source_variable, [source_variable])])
        visited = set()

        while queue:
            current_variable, path = queue.popleft()

            if current_variable == target_variable:
                return path

            if current_variable in visited:
                continue

            visited.add(current_variable)

            for dependent_variable in self.adjacency_list.get(current_variable, set()):
                queue.append(
                    (
                        dependent_variable,
                        path + [dependent_variable],
                    )
                )

        return []