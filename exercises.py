"""
Sammlung von vordefinierten Übungsaufgaben
"""


class PredefinedExercises:
    """
    Sammlung von vordefinierten Übungsaufgaben für Subnetting
    Kombiniert VLSM- und Equal-Subnetting-Aufgaben
    """

    def __init__(self, vlsm_solver, equal_solver):
        self.vlsm_solver = vlsm_solver
        self.equal_solver = equal_solver

    def run_all(self) -> None:
        """
        Führt alle vordefinierten Übungsaufgaben nacheinander aus
        Kombiniert verschiedene Schwierigkeitsgrade und Aufgabentypen
        """
        exercises = [
            # Equal Subnetting Aufgaben
            ("120.50.16.0/20", 4, "Aufgabe 1", "equal"),
            ("10.0.0.0/8", 4096, "Aufgabe 2", "equal"),

            # VLSM Aufgaben mit unterschiedlichen Host-Anforderungen
            ("192.174.2.0/23", [200, 120, 65], "Aufgabe 3", "vlsm"),
            ("172.16.0.0/18", [8000, 1600, 231, 8, 2], "Aufgabe 4", "vlsm"),
            ("10.0.192.0/20", [400, 250, 240, 88, 70, 40], "Aufgabe 5", "vlsm"),
            ("10.80.16.0/20", [250, 126, 70, 15], "Aufgabe 6", "vlsm"),
            ("192.168.4.0/22", [100, 79, 54, 22, 8], "Aufgabe 7", "vlsm"),
            ("10.16.76.0/22", [223, 44, 30], "Aufgabe 8", "vlsm"),
        ]

        for network, requirements, name, exercise_type in exercises:
            if exercise_type == "equal":
                self.equal_solver.solve(network, requirements, name)
            else:

                self.vlsm_solver.solve(network, requirements, name)