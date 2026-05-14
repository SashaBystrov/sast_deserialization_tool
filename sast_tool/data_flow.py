from dataclasses import dataclass, field


@dataclass
class DataFlowGraph:
    """
    Направленный граф, используемый для представления зависимостей данных между переменными.
    """

    edges: dict[str, set[str]] = field(default_factory=dict)
    reverse_edges: dict[str, set[str]] = field(default_factory=dict)

    def add_dependency(self, source_variable: str, target_variable: str) -> None:
        """
        Добавляет зависимость данных между двумя переменными[cite: 7].
        """
        # Прямой граф для распространения пометок
        self.edges.setdefault(source_variable, set()).add(target_variable)

        # Реверсивный граф для восстановления пути (trace)[cite: 7]
        self.reverse_edges.setdefault(target_variable, set()).add(source_variable)

    def propagate_taint(self, initially_tainted_variables: set[str]) -> set[str]:
        """
        Распространяет метки "загрязненности" по графу до достижения стабильного состояния[cite: 7].
        """
        tainted_variables = set(initially_tainted_variables)
        has_changes = True

        while has_changes:
            has_changes = False

            for source_variable, target_variables in self.edges.items():
                if source_variable not in tainted_variables:
                    continue

                for target_variable in target_variables:
                    if target_variable not in tainted_variables:
                        tainted_variables.add(target_variable)
                        has_changes = True

        return tainted_variables

    def get_taint_path(self, source_variables: set[str], target_variable: str) -> list[str]:
        visited = set()
        path: list[str] = []

        def dfs(current: str) -> bool:
            if current in visited:
                return False
            visited.add(current)

            # Если дошли до источника, начинаем строить путь[cite: 7]
            if current in source_variables:
                path.append(current)
                return True

            for parent in self.reverse_edges.get(current, []):
                if dfs(parent):
                    path.append(current)  # Добавляем текущий узел ПОСЛЕ родителя[cite: 7]
                    return True
            return False

        dfs(target_variable)
        return path  # Убираем reversed, если логика dfs уже строит путь от источника[cite: 7]