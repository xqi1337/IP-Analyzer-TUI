"""
Hauptbenutzeroberfläche des IP-Analyzers
"""

import ipaddress
import logging
from pathlib import Path
from typing import Optional, List
from config_manager import ConfigurationManager
from subnetting_calculator import SubnettingCalculator
from ipv6_analyzer import IPv6Analyzer
from vlsm_solver import VLSMSolver
from equal_solver import EqualSubnettingSolver
from exercises import PredefinedExercises

logger = logging.getLogger(__name__)


class UserInterface:
    """
    Erweiterte Benutzeroberfläche mit Konfiguration und Export-Features
    Hauptklasse für die Interaktion mit dem Benutzer
    """

    def __init__(self):
        self.config = ConfigurationManager()
        self.calculator = SubnettingCalculator()
        self.ipv6_analyzer = IPv6Analyzer()
        self.vlsm_solver = VLSMSolver(self.calculator)
        self.equal_solver = EqualSubnettingSolver(self.calculator)
        self.exercises = PredefinedExercises(self.vlsm_solver, self.equal_solver)

        # Export-Verzeichnis erstellen
        export_dir = Path(self.config.get('export_directory', './exports'))
        export_dir.mkdir(parents=True, exist_ok=True)

        # Logging-Level setzen
        log_level = self.config.get('logging_level', 'INFO')
        logging.getLogger().setLevel(getattr(logging, log_level))

    def run(self) -> None:
        """Hauptschleife der Anwendung"""
        self._print_welcome()

        while True:
            choice: str = input("Wählen Sie eine Option 0-9: ").strip()

            match choice:
                case '0':
                    self._handle_exit()
                    break
                case '1':
                    self._handle_ipv6_analysis()
                case '2':
                    self._handle_vlsm_task()
                case '3':
                    self._handle_equal_subnets()
                case '4':
                    self._handle_predefined_exercises()
                case '5':
                    self._handle_custom_vlsm_task()
                case '6':
                    self._handle_quick_vlsm_input()
                case '7':
                    self._handle_export_menu()
                case '8':
                    self._handle_history_menu()
                case '9':
                    self._handle_settings_menu()
                case _:
                    print("Ungültige Option!")

            print("\n" + "=" * 80)

    def _print_welcome(self) -> None:
        """Druckt die erweiterte Willkommensnachricht"""
        print("=" * 80)
        print("         IP-Analyzer mit Subnetting-Aufgaben-Löser (Enhanced)")
        print("=" * 80)
        print("Hauptfunktionen:")
        print("[0] Beenden")
        print("[1] IPv6-Analyse (Hex/Binär)")
        print("[2] VLSM-Aufgabe (Host-Liste eingeben)")
        print("[3] Gleiche Subnetze (Anzahl eingeben)")
        print("[4] Alle Übungsaufgaben lösen")
        print("[5] Benutzerdefinierte VLSM-Aufgabe erstellen")
        print("[6] Schnelle VLSM-Eingabe (Netz + Hosts)")
        print("\nErweiterte Funktionen:")
        print("[7] Export-Menü")
        print("[8] Historie anzeigen")
        print("[9] Einstellungen")
        print()

    def _handle_exit(self) -> None:
        """Behandelt das ordnungsgemäße Beenden der Anwendung"""
        print("Auf Wiedersehen!")
        logger.info("Anwendung beendet")

    def _handle_ipv6_analysis(self) -> None:
        """Behandelt IPv6-Analyse mit optionalem Export"""
        print("\n--- IPv6-Analyse ---")
        ipv6_input: str = input("IPv6‑Adresse (Hex oder Binär): ").strip()
        result = self.ipv6_analyzer.analyze(ipv6_input)

        if result:
            export_choice = input("\nMöchten Sie das Ergebnis exportieren? (j/n): ").strip().lower()
            if export_choice in ['j', 'ja', 'y', 'yes']:
                filename = input(
                    "Dateiname (ohne .json): ").strip() or f"ipv6_analysis_{len(self.ipv6_analyzer.get_analysis_history())}"
                export_path = Path(self.config.get('export_directory')) / f"{filename}.json"
                if self.ipv6_analyzer.export_history(str(export_path)):
                    print(f"✓ Ergebnis exportiert nach: {export_path}")

    def _handle_vlsm_task(self) -> None:
        """Behandelt manuelle VLSM-Aufgaben-Eingabe"""
        print("\n--- VLSM-Aufgabe lösen ---")
        network: str = input("Ausgangsnetz (z.B. 192.174.2.0/23): ").strip()
        hosts_str: str = input("Benötigte Hosts pro Subnetz (getrennt durch Komma): ").strip()

        try:
            hosts_list: List[int] = [int(x.strip()) for x in hosts_str.split(',')]
            self.vlsm_solver.solve(network, hosts_list)
        except ValueError:
            self._print_invalid_input()

    def _handle_equal_subnets(self) -> None:
        """Behandelt Equal-Subnetting-Aufgaben"""
        print("\n--- Gleiche Subnetze ---")
        network: str = input("Ausgangsnetz (z.B. 192.174.2.0/23): ").strip()

        try:
            num_subnets: int = int(input("Anzahl gleicher Subnetze: "))
            self.equal_solver.solve(network, num_subnets, "Manuelle Equal-Subnetting-Aufgabe")
        except ValueError:
            self._print_invalid_input()

    def _handle_predefined_exercises(self) -> None:
        """Behandelt die Ausführung aller vordefinierten Übungsaufgaben"""
        print("\n--- Alle Übungsaufgaben ---")
        self.exercises.run_all()

    def _handle_custom_vlsm_task(self) -> None:
        """Behandelt die Erstellung benutzerdefinierter VLSM-Aufgaben"""
        print("\n--- Benutzerdefinierte VLSM-Aufgabe ---")

        network: Optional[ipaddress.IPv4Network] = self._get_network_input()
        if network is None:
            return

        num_subnets: Optional[int] = self._get_subnet_count()
        if num_subnets is None:
            return

        hosts_requirements: Optional[List[int]] = self._get_host_requirements(num_subnets)
        if hosts_requirements is None:
            return

        if self._confirm_vlsm_task(network, num_subnets, hosts_requirements):
            self.vlsm_solver.solve(
                str(network),
                hosts_requirements,
                f"Benutzerdefinierte Aufgabe ({num_subnets} Subnetze)"
            )
        else:
            print("Berechnung abgebrochen.")

    def _handle_quick_vlsm_input(self) -> None:
        """Behandelt schnelle VLSM-Eingabe in einer Zeile"""
        print("\n--- Schnelle VLSM-Eingabe ---")
        print("Format: Netz-ID/CIDR Hosts1,Hosts2,Hosts3,...")
        print("Beispiel: 192.168.0.0/24 50,30,20,10")

        input_line: str = input("Eingabe: ").strip()

        try:
            parts: List[str] = input_line.split(' ', 1)
            if len(parts) != 2:
                print("Ungültiges Format! Verwenden Sie: Netz-ID/CIDR Hosts1,Hosts2,...")
                return

            network_str, hosts_str = parts
            hosts_list: List[int] = [int(x.strip()) for x in hosts_str.split(',')]

            ipaddress.IPv4Network(network_str, strict=False)
            self.vlsm_solver.solve(network_str, hosts_list, "Schnelle VLSM-Eingabe")

        except (ValueError, ipaddress.AddressValueError) as e:
            print(f"Ungültige Eingabe: {e}")

    def _handle_export_menu(self) -> None:
        """Behandelt das Export-Menü"""
        print("\n--- Export-Menü ---")
        print("[1] VLSM-Ergebnisse exportieren")
        print("[2] Equal-Subnetting-Ergebnisse exportieren")
        print("[3] IPv6-Analyse-Historie exportieren")
        print("[4] Alle Daten exportieren")
        print("[0] Zurück")

        choice = input("Wählen Sie eine Option: ").strip()
        export_dir = Path(self.config.get('export_directory'))

        match choice:
            case '1':
                filename = export_dir / "vlsm_results.json"
                if self.vlsm_solver.export_results(str(filename)):
                    print(f"✓ VLSM-Ergebnisse exportiert nach: {filename}")
            case '2':
                filename = export_dir / "equal_subnetting_results.json"
                if self.equal_solver.export_results(str(filename)):
                    print(f"✓ Equal-Subnetting-Ergebnisse exportiert nach: {filename}")
            case '3':
                filename = export_dir / "ipv6_analysis_history.json"
                if self.ipv6_analyzer.export_history(str(filename)):
                    print(f"✓ IPv6-Analyse-Historie exportiert nach: {filename}")
            case '4':
                self._export_all_data(export_dir)
            case '0':
                return
            case _:
                print("Ungültige Option!")

    def _export_all_data(self, export_dir: Path) -> None:
        """Exportiert alle verfügbaren Daten"""
        success_count = 0
        total_exports = 3

        if self.vlsm_solver.export_results(str(export_dir / "vlsm_results.json")):
            success_count += 1

        if self.equal_solver.export_results(str(export_dir / "equal_subnetting_results.json")):
            success_count += 1

        if self.ipv6_analyzer.export_history(str(export_dir / "ipv6_analysis_history.json")):
            success_count += 1

        print(f"✓ {success_count}/{total_exports} Exporte erfolgreich nach: {export_dir}")

    def _handle_history_menu(self) -> None:
        """Behandelt das Historie-Menü"""
        print("\n--- Historie-Menü ---")
        print("[1] VLSM-Lösungs-Historie anzeigen")
        print("[2] Equal-Subnetting-Historie anzeigen")
        print("[3] IPv6-Analyse-Historie anzeigen")
        print("[0] Zurück")

        choice = input("Wählen Sie eine Option: ").strip()

        match choice:
            case '1':
                self._show_vlsm_history()
            case '2':
                self._show_equal_history()
            case '3':
                self._show_ipv6_history()
            case '0':
                return
            case _:
                print("Ungültige Option!")

    def _show_vlsm_history(self) -> None:
        """Zeigt die VLSM-Lösungs-Historie an"""
        history = self.vlsm_solver.get_solve_history()
        if not history:
            print("Keine VLSM-Historie vorhanden.")
            return

        print(f"\n--- VLSM-Historie ({len(history)} Einträge) ---")
        for i, entry in enumerate(history[-5:], 1):
            print(f"{i}. {entry.get('exercise_name', 'Unbenannt')} - Netz: {entry['network']}")
            if 'statistics' in entry:
                print(f"   Effizienz: {entry['statistics']['efficiency']:.2f}%")

    def _show_equal_history(self) -> None:
        """Zeigt die Equal-Subnetting-Historie an"""
        history = self.equal_solver.get_solve_history()
        if not history:
            print("Keine Equal-Subnetting-Historie vorhanden.")
            return

        print(f"\n--- Equal-Subnetting-Historie ({len(history)} Einträge) ---")
        for i, entry in enumerate(history[-5:], 1):
            print(f"{i}. {entry.get('exercise_name', 'Unbenannt')} - Netz: {entry['network']}")
            print(f"   Subnetze: {entry['created_subnets']}, Effizienz: {entry['efficiency']:.2f}%")

    def _show_ipv6_history(self) -> None:
        """Zeigt die IPv6-Analyse-Historie an"""
        history = self.ipv6_analyzer.get_analysis_history()
        if not history:
            print("Keine IPv6-Analyse-Historie vorhanden.")
            return

        print(f"\n--- IPv6-Analyse-Historie ({len(history)} Einträge) ---")
        for i, entry in enumerate(history[-5:], 1):
            print(f"{i}. Original: {entry['original']}")
            print(f"   Komprimiert: {entry['compressed']}")

    def _handle_settings_menu(self) -> None:
        """Behandelt das Einstellungsmenü"""
        print("\n--- Einstellungen ---")
        print("[1] Aktuelle Einstellungen anzeigen")
        print("[2] Export-Verzeichnis ändern")
        print("[3] Maximale Historie-Einträge ändern")
        print("[4] Logging-Level ändern")
        print("[5] Auf Standardwerte zurücksetzen")
        print("[0] Zurück")

        choice = input("Wählen Sie eine Option: ").strip()

        match choice:
            case '1':
                self._show_current_settings()
            case '2':
                self._change_export_directory()
            case '3':
                self._change_max_history()
            case '4':
                self._change_logging_level()
            case '5':
                self._reset_settings()
            case '0':
                return
            case _:
                print("Ungültige Option!")

    def _show_current_settings(self) -> None:
        """Zeigt alle aktuellen Konfigurationseinstellungen an"""
        print("\n--- Aktuelle Einstellungen ---")
        for key, value in self.config.config.items():
            print(f"{key}: {value}")

    def _change_export_directory(self) -> None:
        """Ändert das Export-Verzeichnis"""
        current = self.config.get('export_directory')
        print(f"Aktuelles Export-Verzeichnis: {current}")
        new_dir = input("Neues Export-Verzeichnis: ").strip()
        if new_dir:
            Path(new_dir).mkdir(parents=True, exist_ok=True)
            self.config.set('export_directory', new_dir)
            print(f"✓ Export-Verzeichnis geändert zu: {new_dir}")

    def _change_max_history(self) -> None:
        """Ändert die maximale Anzahl Historie-Einträge"""
        current = self.config.get('max_history_entries')
        print(f"Aktuelle max. Historie-Einträge: {current}")
        try:
            new_max = int(input("Neue maximale Anzahl: ").strip())
            if new_max > 0:
                self.config.set('max_history_entries', new_max)
                print(f"✓ Maximale Historie-Einträge geändert zu: {new_max}")
            else:
                print("Wert muss größer als 0 sein!")
        except ValueError:
            print("Ungültige Eingabe!")

    def _change_logging_level(self) -> None:
        """Ändert das Logging-Level"""
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        current = self.config.get('logging_level')
        print(f"Aktuelles Logging-Level: {current}")
        print("Verfügbare Level:", ', '.join(levels))
        new_level = input("Neues Logging-Level: ").strip().upper()
        if new_level in levels:
            self.config.set('logging_level', new_level)
            logging.getLogger().setLevel(getattr(logging, new_level))
            print(f"✓ Logging-Level geändert zu: {new_level}")
        else:
            print("Ungültiges Logging-Level!")

    def _reset_settings(self) -> None:
        """Setzt alle Einstellungen auf Standardwerte zurück"""
        confirm = input("Möchten Sie wirklich alle Einstellungen zurücksetzen? (j/n): ").strip().lower()
        if confirm in ['j', 'ja', 'y', 'yes']:
            self.config.reset_to_defaults()
            print("✓ Einstellungen auf Standardwerte zurückgesetzt")

    def _get_network_input(self) -> Optional[ipaddress.IPv4Network]:
        """Interaktive Eingabe und Validierung eines IPv4-Netzwerks"""
        while True:
            network_input: str = input("Ausgangsnetz mit CIDR (z.B. 192.168.0.0/24): ").strip()
            try:
                network: ipaddress.IPv4Network = ipaddress.IPv4Network(network_input, strict=False)
                print(f"✓ Ausgangsnetz: {network}")
                print(f"  Verfügbare IPs: {network.num_addresses}")
                print(f"  Verfügbare Hosts: {network.num_addresses - 2}")
                return network
            except ipaddress.AddressValueError:
                print("Ungültiges Netzwerk! Format: IP/CIDR (z.B. 192.168.0.0/24)")

    def _get_subnet_count(self) -> Optional[int]:
        """Interaktive Eingabe und Validierung der Subnetz-Anzahl"""
        while True:
            try:
                num_subnets: int = int(input("\nAnzahl der Subnetze: ").strip())
                if num_subnets <= 0:
                    print("Anzahl muss größer als 0 sein!")
                    continue
                return num_subnets
            except ValueError:
                self._print_invalid_input()

    def _get_host_requirements(self, num_subnets: int) -> Optional[List[int]]:
        """Interaktive Eingabe der Host-Anforderungen"""
        print(f"\nGeben Sie die Host-Anforderungen für {num_subnets} Subnetze ein:")
        hosts_requirements: List[int] = []

        for i in range(1, num_subnets + 1):
            while True:
                try:
                    hosts: int = int(input(f"Subnetz {i:2d} - Benötigte Hosts: ").strip())
                    if hosts <= 0:
                        print("Host-Anzahl muss größer als 0 sein!")
                        continue
                    hosts_requirements.append(hosts)
                    break
                except ValueError:
                    self._print_invalid_input()

        return hosts_requirements

    def _confirm_vlsm_task(self, network: ipaddress.IPv4Network, num_subnets: int,
                           hosts_requirements: List[int]) -> bool:
        """Zeigt Zusammenfassung der VLSM-Aufgabe und holt Benutzerbestätigung"""
        print(f"\n--- Zusammenfassung ---")
        print(f"Ausgangsnetz: {network}")
        print(f"Anzahl Subnetze: {num_subnets}")
        print("Host-Anforderungen:")

        total_required_hosts: int = 0
        for i, hosts in enumerate(hosts_requirements, 1):
            print(f"  Subnetz {i:2d}: {hosts:4d} Hosts")
            required_ips: int = 2 ** self.calculator.calculate_host_bits(hosts)
            total_required_hosts += required_ips

        print(f"\nBenötigte IPs gesamt: {total_required_hosts}")
        print(f"Verfügbare IPs:       {network.num_addresses}")

        if total_required_hosts > network.num_addresses:
            print("WARNUNG: Nicht genügend IP-Adressen verfügbar!")
            print("Möglicherweise können nicht alle Subnetze erstellt werden.")
        else:
            print("Genügend IP-Adressen verfügbar")

        proceed: str = input("\nMöchten Sie die VLSM-Berechnung durchführen? (j/n): ").strip().lower()
        return proceed in ['j', 'ja', 'y', 'yes']

    def _print_invalid_input(self) -> None:
        """Standardisierte Fehlermeldung für ungültige Benutzereingaben"""
        print("Ungültige Eingabe! Bitte versuchen Sie es erneut.")