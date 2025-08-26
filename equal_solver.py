"""
Equal Subnetting Solver für gleich große Subnetze
Implementiert die Berechnung und Darstellung von gleich großen IP-Subnetzen
"""

# IMPORT STATEMENTS
# ///////////////////////////////////////////////////////////////
import ipaddress
import logging
import json
from typing import List, Optional, Dict, Union
from subnetting_calculator import SubnettingSolver

# LOGGER CONFIGURATION
# ///////////////////////////////////////////////////////////////
logger = logging.getLogger(__name__)


# DATA CLASSES
# ///////////////////////////////////////////////////////////////
class EqualSubnettingSolver(SubnettingSolver):
    """
    Klasse für die Berechnung von gleich großen IP-Subnetzen
    
    Diese Klasse implementiert die Equal-Subnetting-Methode, bei der ein
    gegebenes IP-Netzwerk in eine bestimmte Anzahl von gleich großen 
    Subnetzen unterteilt wird.
    
    Attributes:
        _solve_history: Liste der durchgeführten Subnetting-Berechnungen
    """

    def __init__(self, calculator):
        """
        Initialisiert den EqualSubnettingSolver
        
        Args:
            calculator: Eine Instanz des SubnettingCalculators für Berechnungen
        """
        super().__init__(calculator)
        # Historie aller durchgeführten Equal-Subnetting-Berechnungen
        self._solve_history: List[Dict[str, Union[str, int, List[Dict]]]] = []

    def solve(self, network_str: str, num_subnets: int, exercise_name: str = "") -> Optional[
        List[ipaddress.IPv4Network]]:
        """
        Löst Equal-Subnetting-Aufgaben durch Berechnung gleich großer Subnetze
        
        Diese Methode teilt ein gegebenes IP-Netzwerk in eine bestimmte Anzahl
        von gleich großen Subnetzen auf und berechnet alle relevanten Parameter.
        
        Args:
            network_str: IP-Netzwerk als String (z.B. "192.168.1.0/24")
            num_subnets: Anzahl der gewünschten Subnetze
            exercise_name: Optionaler Name für die Aufgabe (für Historie)
            
        Returns:
            Optional[List[ipaddress.IPv4Network]]: Liste der erstellten Subnetze
            oder None bei Fehlern
        """
        logger.info(f"Löse Equal-Subnetting-Aufgabe: {exercise_name or 'Unbenannt'}")

        # Eingabe-Validierung: IPv4-Netzwerk parsen
        try:
            network: ipaddress.IPv4Network = ipaddress.IPv4Network(network_str, strict=False)
        except ipaddress.AddressValueError as e:
            logger.error(f"Ungültiges IPv4-Netzwerk: {e}")
            print("Ungültiges IPv4-Netzwerk!")
            return None

        # Header-Ausgabe für bessere Übersicht
        self._print_header(network, num_subnets, exercise_name)

        # Berechnung der benötigten Subnetz-Bits
        # Formel: 2^subnet_bits >= num_subnets
        subnet_bits: int = self.calculator.calculate_subnet_bits(num_subnets)
        new_prefix: int = network.prefixlen + subnet_bits

        # Validierung: Maximal /30 Netzwerke (2 Hosts) sind sinnvoll
        if new_prefix > 30:
            logger.warning("Zu viele Subnetze angefordert")
            print("Fehler: Zu viele Subnetze!")
            return None

        # Subnetz-Erstellung mit der neuen Präfixlänge
        subnets: List[ipaddress.IPv4Network] = list(network.subnets(new_prefix=new_prefix))
        
        # Berechnung der Host-Bits und Sprungweite
        # Host-Bits = 32 - Präfixlänge
        # Sprungweite = 2^Host-Bits (Anzahl IP-Adressen pro Subnetz)
        host_bits: int = 32 - new_prefix
        jump_width: int = 2 ** host_bits

        # Tabellen-Ausgabe der Subnetze
        self._print_subnets(subnets, new_prefix, jump_width)

        # Effizienz-Statistiken berechnen
        # Nur die angeforderte Anzahl von Subnetzen wird für Effizienz gezählt
        requested_subnets = min(num_subnets, len(subnets))
        total_available_hosts = requested_subnets * (jump_width - 2)  # -2 für Netz- und Broadcast-Adresse
        efficiency = (requested_subnets * (jump_width - 2)) / network.num_addresses * 100

        print(f"\nEffizienz-Statistiken:")
        print(f"  Angeforderte Subnetze: {num_subnets}")
        print(f"  Erstelle Subnetze: {len(subnets)}")
        print(f"  Hosts pro Subnetz: {jump_width - 2}")
        print(f"  Gesamt nutzbare Hosts: {total_available_hosts}")
        print(f"  Netzwerk-Effizienz: {efficiency:.2f}%")

        solve_data = {
            'network': network_str,
            'exercise_name': exercise_name,
            'num_subnets': num_subnets,
            'created_subnets': len(subnets),
            'hosts_per_subnet': jump_width - 2,
            'efficiency': efficiency,
            'subnets': [{'network': str(subnet), 'cidr': subnet.prefixlen} for subnet in subnets[:4]]
        }
        self._solve_history.append(solve_data)

        return subnets

    def _print_header(self, network: ipaddress.IPv4Network, num_subnets: int, exercise_name: str) -> None:
        """
        Druckt den formatierten Header für die Subnetting-Ausgabe
        
        Args:
            network: Das IPv4-Netzwerk-Objekt
            num_subnets: Anzahl der gewünschten Subnetze
            exercise_name: Name der Aufgabe für Identifikation
        """
        # Trennlinie für bessere Lesbarkeit (80 Zeichen)
        print(f"\n{'=' * 80}")
        
        # Aufgabenname (falls vorhanden)
        if exercise_name:
            print(f"Aufgabe: {exercise_name}")
            
        # Grundlegende Netzwerk-Informationen
        print(f"Ausgangsnetz: {network}")
        print(f"Subnetzmaske: {network.netmask}")
        print(f"Subnetting-Ziel: {num_subnets} gleichgroße Netze")
        
        # Abschließende Trennlinie
        print(f"{'=' * 80}")

    def _print_subnets(self, subnets: List[ipaddress.IPv4Network], new_prefix: int, jump_width: int) -> None:
        """
        Druckt die formatierte Subnetz-Tabelle mit allen relevanten Informationen
        
        Args:
            subnets: Liste der generierten IPv4-Subnetze
            new_prefix: Die neue CIDR-Präfixlänge für alle Subnetze
            jump_width: Sprungweite zwischen Subnetzen (Anzahl IP-Adressen)
        """
        # Tabellen-Header mit fester Spaltenbreite
        print(f"{'':12} | {'Subnetz-ID':<15} | {'CIDR':<5} | {'Host-IP-Range':<30} | {'Broadcast':<15} | {'Hosts':<6}")
        print("-" * 95)

        # Maximale Anzahl anzuzeigender Subnetze (Begrenzung für Übersichtlichkeit)
        max_show: int = min(12, len(subnets))
        
        # Iteration durch die ersten 12 Subnetze
        for i in range(max_show):
            subnet: ipaddress.IPv4Network = subnets[i]
            
            # Berechnung der nutzbaren Host-IP-Adressen
            # Erste Host-IP: Netzwerk-Adresse + 1
            # Letzte Host-IP: Broadcast-Adresse - 1
            first_host: ipaddress.IPv4Address = subnet.network_address + 1
            last_host: ipaddress.IPv4Address = subnet.broadcast_address - 1
            host_range: str = f"{str(first_host)} bis {str(last_host)}"
            
            # Anzahl nutzbarer Hosts: Alle Adressen - Netzwerk - Broadcast
            host_count: int = subnet.num_addresses - 2

            # Formatierte Ausgabe einer Subnetz-Zeile
            print(
                f"Subnetz {i + 1}:   | {str(subnet.network_address):<15} | /{new_prefix:<4} | "
                f"{host_range:<30} | {str(subnet.broadcast_address):<15} | {host_count:<6}"
            )

        # Ellipsis wenn mehr als 12 Subnetze vorhanden
        if len(subnets) > 12:
            print("...")

        # Sprungweite-Information (wichtig für manueller Berechnung)
        print(f"Sprungweite: | {jump_width:<15} | {'':5} | {'':30} | {'':15} | {'':6}")

    def get_solve_history(self) -> List[Dict[str, Union[str, int, List[Dict]]]]:
        """
        Gibt eine Kopie der Equal-Subnetting-Historie zurück
        
        Returns:
            List[Dict]: Kopie der Historie aller durchgeführten Berechnungen
        """
        # Kopie zurückgeben um Manipulation der internen Daten zu verhindern
        return self._solve_history.copy()

    def export_results(self, filename: str) -> bool:
        """
        Exportiert alle Equal-Subnetting-Ergebnisse in eine JSON-Datei
        
        Args:
            filename: Pfad zur Ziel-JSON-Datei
            
        Returns:
            bool: True bei erfolgreichem Export, False bei Fehlern
        """
        try:
            # JSON-Export mit UTF-8 Encoding für deutsche Umlaute
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self._solve_history, f, indent=2, ensure_ascii=False)
            
            # Erfolgs-Logging
            logger.info(f"Equal-Subnetting-Ergebnisse erfolgreich exportiert nach: {filename}")
            return True
            
        except Exception as e:
            # Fehler-Behandlung und Logging
            logger.error(f"Fehler beim Exportieren der Equal-Subnetting-Ergebnisse: {e}")
            return False