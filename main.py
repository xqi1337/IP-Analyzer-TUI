"""
IP-Analyzer (Hex/Binär) mit Subnetting Berechnungen
- VLSM-Aufgaben mit benutzerdefinierten Host-Anforderungen
- Gleich große Subnetze
- Vordefinierte Übungsaufgaben

Hauptfunktionen:
- IPv6-Adressanalyse mit Hex/Binär-Konvertierung
- VLSM (Variable Length Subnet Masking) Berechnungen
- Equal Subnetting für gleich große Subnetze
- Export/Import von Ergebnissen
- Historie-Verwaltung und Konfiguration
"""

# IMPORT STATEMENTS
# ///////////////////////////////////////////////////////////////
from __future__ import annotations  # Ermöglicht moderne Type Hints
import ipaddress  # Python-Bibliothek für IP-Adress-Manipulation
import math  # Mathematische Funktionen für Berechnungen
import logging  # Logging-System für Debugging und Monitoring
from typing import List, Tuple, Optional, Union, Dict, Protocol  # Type Hints
from dataclasses import dataclass, field  # Datenklassen für strukturierte Daten
from enum import Enum  # Enumerationen für typsichere Konstanten
from abc import ABC, abstractmethod  # Abstract Base Classes
import json  # JSON-Serialisierung für Export/Import
from pathlib import Path  # Pfad-Manipulation für Dateien

# LOGGING CONFIGURATION
# ///////////////////////////////////////////////////////////////
# Logging-System konfigurieren mit Zeitstempel und Log-Level
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ENUMERATIONS
# ///////////////////////////////////////////////////////////////
class IPv6BlockRole(Enum):
    """
    IPv6-Block-Rollen für bessere Klassifizierung der Adressteile
    Jeder Block einer IPv6-Adresse hat eine spezielle Funktion
    """
    GLOBAL_ROUTING_PREFIX = "Global Routing Prefix"  # Erste 3 Blöcke für globales Routing
    SUBNET_ID = "Subnetz‑ID"  # 4. Block für Subnetz-Identifikation
    INTERFACE_IDENTIFIER = "Interface Identifier"  # Letzten 4 Blöcke für Interface-ID


class OctetType(Enum):
    """
    Oktett-Typen für Sprungweiten-Berechnung bei IPv4-Subnetting
    Definiert welches Oktett bei der Subnetz-Berechnung betroffen ist
    """
    FIRST = "1. Oktett"  # 1. Oktett (höchstwertige 8 Bits)
    SECOND = "2. Oktett"  # 2. Oktett
    THIRD = "3. Oktett"  # 3. Oktett
    FOURTH = "4. Oktett"  # 4. Oktett (niederwertige 8 Bits)


# DATA CLASSES
# ///////////////////////////////////////////////////////////////
@dataclass
class JumpWidth:
    """
    Sprungweite-Information für Subnetting-Berechnungen
    Enthält die Sprungweite und das betroffene Oktett
    """
    width: int  # Sprungweite (z.B. 256, 64, 4)
    affected_octet: OctetType  # Betroffenes Oktett

    def __str__(self) -> str:
        """String-Darstellung für Ausgabe in Tabellen"""
        return f"{self.width} ({self.affected_octet.value})"


@dataclass
class SubnetResult:
    """
    Ergebnis einer Subnetz-Berechnung mit allen relevanten Informationen
    Wird für VLSM-Berechnungen verwendet und kann exportiert werden
    """
    subnet_number: int  # Nummer des Subnetzes (1, 2, 3, ...)
    hosts_needed: int  # Benötigte Anzahl Hosts
    total_ips: int  # Gesamtanzahl IPs im Subnetz (inkl. Netz- und Broadcast-Adresse)
    network: ipaddress.IPv4Network  # IPv4Network-Objekt des Subnetzes
    jump_width: JumpWidth  # Sprungweite-Information
    first_host: ipaddress.IPv4Address  # Erste verwendbare Host-IP
    last_host: ipaddress.IPv4Address  # Letzte verwendbare Host-IP
    efficiency: float = field(init=False)  # Effizienz in % (wird automatisch berechnet)

    def __post_init__(self) -> None:
        """
        Wird nach der Initialisierung automatisch aufgerufen
        Berechnet die Effizienz des Subnetzes (verwendete vs. verfügbare Hosts)
        """
        # Effizienz = (benötigte Hosts / verfügbare Hosts) * 100
        # -2 weil Netz- und Broadcast-Adresse nicht als Hosts verwendbar sind
        self.efficiency = (self.hosts_needed / (self.total_ips - 2)) * 100

    def to_dict(self) -> Dict[str, Union[str, int, float]]:
        """
        Konvertiert das Subnetz-Ergebnis zu einem Dictionary für JSON-Export
        Alle IP-Adressen werden zu Strings konvertiert für Serialisierung
        """
        return {
            'subnet_number': self.subnet_number,
            'hosts_needed': self.hosts_needed,
            'total_ips': self.total_ips,
            'network_address': str(self.network.network_address),  # Netzwerk-Adresse als String
            'cidr': self.network.prefixlen,  # CIDR-Notation (/24, /25, etc.)
            'netmask': str(self.network.netmask),  # Subnetzmaske als String
            'first_host': str(self.first_host),
            'last_host': str(self.last_host),
            'broadcast': str(self.network.broadcast_address),  # Broadcast-Adresse als String
            'efficiency_percent': round(self.efficiency, 2),  # Effizienz gerundet auf 2 Dezimalstellen
            'jump_width': self.jump_width.width,
            'affected_octet': self.jump_width.affected_octet.value
        }


@dataclass
class NetworkStatistics:
    """
    Statistiken für ein Netzwerk nach der Subnetz-Berechnung
    Zeigt Gesamteffizienz und Ressourcenverbrauch an
    """
    total_networks: int  # Gesamtanzahl erstellter Subnetze
    total_hosts_available: int  # Gesamtanzahl verfügbarer Host-Adressen
    total_hosts_used: int  # Gesamtanzahl tatsächlich benötigter Hosts
    overall_efficiency: float  # Gesamteffizienz in Prozent
    unused_networks: int  # Anzahl ungenutzter IP-Adressen

    def __str__(self) -> str:
        """String-Darstellung für Ausgabe der Statistiken"""
        return (
            f"Netzwerk-Statistiken:\n"
            f"  Gesamte Subnetze: {self.total_networks}\n"
            f"  Verfügbare Hosts: {self.total_hosts_available}\n"
            f"  Verwendete Hosts: {self.total_hosts_used}\n"
            f"  Gesamteffizienz: {self.overall_efficiency:.2f}%\n"
            f"  Ungenutzte Hosts: {self.total_hosts_available - self.total_hosts_used}"
        )


# PROTOCOLS AND ABSTRACT CLASSES
# ///////////////////////////////////////////////////////////////
class NetworkAnalyzer(Protocol):
    """
    Protocol (Interface) für Network-Analyzer Klassen
    Definiert die erforderliche analyze-Methode
    """

    def analyze(self, address: str) -> None:
        """Analysiert eine Netzwerk-Adresse"""
        ...


class SubnettingSolver(ABC):
    """
    Abstrakte Basisklasse für alle Subnetting-Solver
    Definiert gemeinsame Eigenschaften und abstrakte Methoden
    """

    def __init__(self, calculator: 'SubnettingCalculator'):
        """Initialisiert den Solver mit einem Calculator"""
        self.calculator = calculator

    @abstractmethod
    def solve(self, network_str: str, *args, **kwargs) -> Optional[
        Union[List[SubnetResult], List[ipaddress.IPv4Network]]]:
        """
        Abstrakte Methode zum Lösen von Subnetting-Problemen
        Muss von allen Unterklassen implementiert werden
        """
        pass


# IPV6 ANALYZER CLASS
# ///////////////////////////////////////////////////////////////
class IPv6Analyzer:
    """
    Klasse für IPv6-Adress-Analyse mit erweiterten Features
    Unterstützt Hex- und Binär-Format, Historie und Export
    """

    def __init__(self):
        """Initialisiert den Analyzer mit leerer Historie"""
        # Liste zur Speicherung aller durchgeführten Analysen
        self._analysis_history: List[Dict[str, str]] = []

    @staticmethod
    def get_block_role(index: int) -> IPv6BlockRole:
        """
        Bestimmt die Rolle eines IPv6-Blocks basierend auf dem Index (0-7)
        IPv6 besteht aus 8 Blöcken zu je 16 Bit
        """
        if index < 3:
            # Erste 3 Blöcke: Global Routing Prefix
            return IPv6BlockRole.GLOBAL_ROUTING_PREFIX
        elif index == 3:
            # 4. Block: Subnetz-ID
            return IPv6BlockRole.SUBNET_ID
        else:
            # Letzten 4 Blöcke: Interface Identifier
            return IPv6BlockRole.INTERFACE_IDENTIFIER

    @staticmethod
    def hex_to_binary(hex_block: str) -> str:
        """
        Konvertiert einen 4-stelligen Hex-Block zu 16-Bit Binär
        Beispiel: "FF00" -> "1111111100000000"
        """
        try:
            # int(hex_block, 16) konvertiert Hex zu Integer
            # bin() konvertiert Integer zu Binär-String (mit "0b" Prefix)
            # [2:] entfernt "0b" Prefix
            # zfill(16) füllt mit Nullen auf 16 Stellen auf
            return bin(int(hex_block, 16))[2:].zfill(16)
        except ValueError as e:
            logger.error(f"Fehler bei Hex-zu-Binär Konvertierung: {e}")
            raise

    @staticmethod
    def binary_to_hex(binary_block: str) -> str:
        """
        Konvertiert einen 16-Bit Binär-Block zu 4-stelligem Hex
        Beispiel: "1111111100000000" -> "FF00"
        """
        try:
            # int(binary_block, 2) konvertiert Binär zu Integer
            # hex() konvertiert Integer zu Hex-String (mit "0x" Prefix)
            # [2:] entfernt "0x" Prefix
            # upper() konvertiert zu Großbuchstaben
            # zfill(4) füllt mit Nullen auf 4 Stellen auf
            return hex(int(binary_block, 2))[2:].upper().zfill(4)
        except ValueError as e:
            logger.error(f"Fehler bei Binär-zu-Hex Konvertierung: {e}")
            raise

    @staticmethod
    def is_binary_ipv6(address: str) -> bool:
        """
        Prüft ob eine IPv6-Adresse in binärer Notation vorliegt
        Binäre Notation enthält nur '0', '1' und ':' Zeichen
        """
        # Entfernt CIDR-Notation (/64) falls vorhanden
        address_clean: str = address.split('/')[0]
        # Erlaubte Zeichen für binäre IPv6-Adresse
        allowed_chars: set[str] = {'0', '1', ':'}
        # Prüft ob alle Zeichen in der Adresse erlaubt sind
        return all(char in allowed_chars for char in address_clean)

    @classmethod
    def convert_binary_to_hex_ipv6(cls, binary_address: str) -> str:
        """
        Konvertiert eine binäre IPv6-Adresse zu Hex-Format
        Behandelt auch CIDR-Notation und verschiedene Block-Längen
        """
        # Trennt Adresse und CIDR-Notation
        address_parts: List[str] = binary_address.split('/')
        address_clean: str = address_parts[0]

        # Trennt Adresse in einzelne Blöcke
        binary_blocks: List[str] = address_clean.split(':')
        hex_blocks: List[str] = []

        # Konvertiert jeden Block einzeln
        for block in binary_blocks:
            if len(block) == 16:
                # Block hat korrekte Länge, direkt konvertieren
                hex_blocks.append(cls.binary_to_hex(block))
            elif len(block) == 0:
                # Leerer Block (für IPv6-Komprimierung ::)
                hex_blocks.append('')
            else:
                # Block zu kurz, mit führenden Nullen auffüllen
                padded_block: str = block.zfill(16)
                hex_blocks.append(cls.binary_to_hex(padded_block))

        # Blöcke wieder zusammenfügen
        hex_address: str = ':'.join(hex_blocks)

        # CIDR-Notation wieder anhängen falls vorhanden
        if len(address_parts) > 1:
            hex_address += '/' + address_parts[1]

        return hex_address

    def analyze(self, address: str) -> Optional[Dict[str, str]]:
        """
        Analysiert eine IPv6-Adresse und gibt detaillierte Informationen aus
        Unterstützt sowohl Hex- als auch Binär-Format
        """
        original_input: str = address
        logger.info(f"Analysiere IPv6-Adresse: {address}")

        try:
            # Prüfung ob Adresse in binärer Notation vorliegt
            if self.is_binary_ipv6(address):
                print(f"Binäre Eingabe erkannt: {address}")
                # Konvertierung zu Hex-Format
                address = self.convert_binary_to_hex_ipv6(address)
                print(f"Konvertiert zu Hex:     {address}")

            # CIDR-Notation entfernen für IPv6Address-Objekt
            address_without_cidr: str = address.split('/')[0]
            # IPv6Address-Objekt erstellen (validiert automatisch)
            ip: ipaddress.IPv6Address = ipaddress.IPv6Address(address_without_cidr)

            # Verschiedene Darstellungsformen erstellen
            expanded: str = ip.exploded  # Vollständige Form: 2001:0db8:0000:0042:0000:8a2e:0370:7334
            compressed: str = ip.compressed  # Komprimierte Form: 2001:db8::42:0:8a2e:370:7334

            # Ergebnis für Historie zusammenstellen
            analysis_result = {
                'original': original_input,
                'hex_format': address if not self.is_binary_ipv6(original_input) else address,
                'expanded': expanded,
                'compressed': compressed
            }

            # Ergebnis zur Historie hinzufügen
            self._analysis_history.append(analysis_result)

            # Ergebnisse ausgeben
            print(f"IPv6‑Adresse Eingabe:   {original_input}")
            if self.is_binary_ipv6(original_input):
                print(f"Konvertiert zu Hex:     {address}")
            print(f"Ausgeschrieben:         {expanded}")
            print(f"Kurzschreibweise:       {compressed}\n")

            # Detaillierte Block-Analyse
            blocks: List[str] = expanded.split(":")
            for i, block in enumerate(blocks):
                # Rolle des Blocks bestimmen
                role: IPv6BlockRole = self.get_block_role(i)
                # Block zu Binär konvertieren
                binary: str = self.hex_to_binary(block)
                print(f"Block {i + 1}: {block.upper()}  | {binary}  → {role.value}")

            return analysis_result

        except (ipaddress.AddressValueError, ValueError) as e:
            # Fehlerbehandlung bei ungültigen Adressen
            logger.error(f"Fehler bei IPv6-Analyse: {e}")
            print(f"Ungültige IPv6‑Adresse: {e}")
            return None

    def get_analysis_history(self) -> List[Dict[str, str]]:
        """
        Gibt eine Kopie der Analyse-Historie zurück
        Verhindert unbeabsichtigte Änderungen an der internen Historie
        """
        return self._analysis_history.copy()

    def export_history(self, filename: str) -> bool:
        """
        Exportiert die Analyse-Historie in eine JSON-Datei
        Verwendet UTF-8 Encoding für korrekte Darstellung von Sonderzeichen
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # JSON mit Einrückung für bessere Lesbarkeit
                # ensure_ascii=False für korrekte UTF-8 Zeichen
                json.dump(self._analysis_history, f, indent=2, ensure_ascii=False)
            logger.info(f"Historie erfolgreich exportiert nach: {filename}")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Exportieren der Historie: {e}")
            return False


# SUBNETTING CALCULATOR CLASS
# ///////////////////////////////////////////////////////////////
class SubnettingCalculator:
    """
    Klasse für grundlegende Subnetting-Berechnungen
    Enthält statische Methoden für mathematische Operationen
    """

    @staticmethod
    def calculate_subnet_bits(num_subnets: int) -> int:
        """
        Berechnet benötigte Subnetz-Bits für eine feste Anzahl von Subnetzen
        Verwendet Logarithmus zur Basis 2 und rundet auf
        """
        # log2(num_subnets) gibt die exakte Anzahl benötigter Bits an
        # ceil() rundet auf die nächste ganze Zahl auf
        return math.ceil(math.log2(num_subnets))

    @staticmethod
    def calculate_host_bits(num_hosts: int) -> int:
        """
        Berechnet die benötigten Host-Bits für eine feste Anzahl von Hosts
        +2 für Netz- und Broadcast-Adresse
        """
        # +2 weil Netz- und Broadcast-Adresse nicht als Hosts verwendbar sind
        return math.ceil(math.log2(num_hosts + 2))

    @staticmethod
    def calculate_jump_width(host_bits: int) -> JumpWidth:
        """
        Berechnet Sprungweite und bestimmt betroffene Oktette
        Basierend auf der Anzahl der Host-Bits
        """
        # Gesamtanzahl IPs = 2^host_bits
        total_ips: int = 2 ** host_bits

        if host_bits <= 8:
            # Bis 8 Host-Bits: Nur 4. Oktett betroffen
            return JumpWidth(total_ips, OctetType.FOURTH)
        elif host_bits <= 16:
            # 9-16 Host-Bits: 3. Oktett betroffen
            jump_3rd: int = total_ips // 256  # Division durch 256 für 3. Oktett
            return JumpWidth(jump_3rd, OctetType.THIRD)
        elif host_bits <= 24:
            # 17-24 Host-Bits: 2. Oktett betroffen
            jump_2nd: int = total_ips // (256 * 256)  # Division durch 256² für 2. Oktett
            return JumpWidth(jump_2nd, OctetType.SECOND)
        else:
            # >24 Host-Bits: 1. Oktett betroffen
            jump_1st: int = total_ips // (256 * 256 * 256)  # Division durch 256³ für 1. Oktett
            return JumpWidth(jump_1st, OctetType.FIRST)


# VLSM SOLVER CLASS
# ///////////////////////////////////////////////////////////////
class VLSMSolver(SubnettingSolver):
    """
    Klasse für VLSM (Variable Length Subnet Masking) Aufgaben
    Erstellt Subnetze unterschiedlicher Größe basierend auf Host-Anforderungen
    """

    def __init__(self, calculator: SubnettingCalculator):
        """Initialisiert VLSM-Solver mit Calculator und leerer Historie"""
        super().__init__(calculator)
        # Historie aller gelösten VLSM-Aufgaben
        self._solve_history: List[Dict[str, Union[str, List[Dict]]]] = []

    def solve(self, network_str: str, host_requirements: List[int], exercise_name: str = "") -> Optional[
        List[SubnetResult]]:
        """
        Löst VLSM-Aufgaben und gibt formatierte Tabelle aus
        Sortiert Host-Anforderungen nach Größe für optimale Platznutzung
        """
        logger.info(f"Löse VLSM-Aufgabe: {exercise_name or 'Unbenannt'}")

        try:
            # IPv4Network-Objekt aus String erstellen
            network: ipaddress.IPv4Network = ipaddress.IPv4Network(network_str, strict=False)
        except ipaddress.AddressValueError as e:
            logger.error(f"Ungültiges IPv4-Netzwerk: {e}")
            print("Ungültiges IPv4-Netzwerk!")
            return None

        # Header und Tabellenkopf ausgeben
        self._print_header(network, exercise_name)
        self._print_table_header()

        # Host-Anforderungen nach Größe sortieren (größte zuerst für optimale Platznutzung)
        sorted_requirements: List[Tuple[int, int]] = sorted(
            enumerate(host_requirements, 1),  # (Subnetz-Nummer, Host-Anzahl)
            key=lambda x: x[1],  # Sortierung nach Host-Anzahl
            reverse=True  # Absteigende Reihenfolge
        )

        # Liste bereits verwendeter Subnetz-Bereiche
        used_space: List[ipaddress.IPv4Network] = []
        # Ergebnisse sammeln
        results: List[SubnetResult] = []

        # Jede Host-Anforderung einzeln bearbeiten
        for subnet_num, hosts_needed in sorted_requirements:
            subnet_result = self._calculate_subnet(
                network, subnet_num, hosts_needed, used_space
            )

            if subnet_result is None:
                # Kein Platz mehr im Netzwerk
                error_msg = f"Fehler: Kein Platz für Subnetz {subnet_num} mit {hosts_needed} Hosts"
                logger.warning(error_msg)
                print(error_msg)
                continue

            # Ergebnis hinzufügen und Zeile ausgeben
            results.append(subnet_result)
            self._print_subnet_row(subnet_result)

        # Statistiken berechnen und anzeigen wenn Ergebnisse vorhanden
        if results:
            stats = self._calculate_statistics(network, results)
            print(f"\n{stats}")

            # Ergebnis in Historie speichern
            solve_data = {
                'network': network_str,
                'exercise_name': exercise_name,
                'host_requirements': host_requirements,
                'results': [result.to_dict() for result in results],
                'statistics': {
                    'total_networks': stats.total_networks,
                    'efficiency': stats.overall_efficiency
                }
            }
            self._solve_history.append(solve_data)

        return results

    def _calculate_subnet(self, base_network: ipaddress.IPv4Network, subnet_num: int,
                          hosts_needed: int, used_space: List[ipaddress.IPv4Network]) -> Optional[SubnetResult]:
        """
        Berechnet ein einzelnes Subnetz basierend auf Host-Anforderungen
        Findet das erste verfügbare Subnetz das nicht mit bereits verwendeten überlappt
        """
        # Benötigte Host-Bits berechnen
        host_bits: int = self.calculator.calculate_host_bits(hosts_needed)
        # Subnetz-Prefix-Länge berechnen (32 - Host-Bits)
        subnet_prefix: int = 32 - host_bits
        # Gesamtanzahl IPs im Subnetz
        total_ips: int = 2 ** host_bits
        # Sprungweite berechnen
        jump_width: JumpWidth = self.calculator.calculate_jump_width(host_bits)

        # Alle möglichen Subnetze der benötigten Größe durchgehen
        for possible_net in base_network.subnets(new_prefix=subnet_prefix):
            # Prüfen ob Subnetz mit bereits verwendeten überlappt
            if not any(possible_net.overlaps(used_net) for used_net in used_space):
                # Subnetz als verwendet markieren
                used_space.append(possible_net)

                # Host-Adressen berechnen (erste und letzte verwendbare IP)
                first_host: ipaddress.IPv4Address = possible_net.network_address + 1
                last_host: ipaddress.IPv4Address = possible_net.broadcast_address - 1

                # SubnetResult-Objekt erstellen und zurückgeben
                return SubnetResult(
                    subnet_number=subnet_num,
                    hosts_needed=hosts_needed,
                    total_ips=total_ips,
                    network=possible_net,
                    jump_width=jump_width,
                    first_host=first_host,
                    last_host=last_host
                )

        # Kein verfügbares Subnetz gefunden
        return None

    def _calculate_statistics(self, base_network: ipaddress.IPv4Network,
                              results: List[SubnetResult]) -> NetworkStatistics:
        """
        Berechnet Netzwerk-Statistiken basierend auf den Subnetz-Ergebnissen
        Zeigt Effizienz und Ressourcenverbrauch an
        """
        total_networks = len(results)
        # Gesamtanzahl verfügbarer Host-Adressen (-2 pro Subnetz für Netz/Broadcast)
        total_hosts_available = sum(result.total_ips - 2 for result in results)
        # Gesamtanzahl tatsächlich benötigter Hosts
        total_hosts_used = sum(result.hosts_needed for result in results)
        # Gesamteffizienz berechnen (verwendet / verfügbar * 100)
        overall_efficiency = (total_hosts_used / total_hosts_available) * 100 if total_hosts_available > 0 else 0
        # Ungenutzte IPs berechnen
        unused_networks = base_network.num_addresses - sum(result.total_ips for result in results)

        return NetworkStatistics(
            total_networks=total_networks,
            total_hosts_available=total_hosts_available,
            total_hosts_used=total_hosts_used,
            overall_efficiency=overall_efficiency,
            unused_networks=unused_networks
        )

    def _print_header(self, network: ipaddress.IPv4Network, exercise_name: str) -> None:
        """Druckt den Header der VLSM-Ausgabe mit Trennlinien"""
        print(f"\n{'=' * 80}")
        if exercise_name:
            print(f"Aufgabe: {exercise_name}")
        print(f"Ausgangsnetz: {network}")
        print(f"{'=' * 80}")

    def _print_table_header(self) -> None:
        """Druckt den formatierten Tabellenkopf für VLSM-Ergebnisse"""
        print(
            f"{'Subnetz':<8} | {'Benötigte':<10} | {'IPs im':<8} | {'Sprungweite':<15} | "
            f"{'Netz-ID':<15} | {'CIDR':<5} | {'Subnetzmaske':<15} | "
            f"{'Host-IP-Range':<25} | {'Broadcast':<15} | {'Effizienz':<10}"
        )
        print(
            f"{'':8} | {'Hosts':<10} | {'Subnetz':<8} | {'(+ Oktett)':<15} | "
            f"{'':<15} | {'':<5} | {'Dezimal':<15} | {'':<25} | {'':<15} | {'%':<10}"
        )
        print("-" * 135)

    def _print_subnet_row(self, result: SubnetResult) -> None:
        """Druckt eine formatierte Zeile der Subnetz-Tabelle"""
        # Host-Range als String formatieren
        host_range: str = f"{str(result.first_host)} - {str(result.last_host)}"

        # Komplette Tabellenzeile ausgeben
        print(
            f"{result.subnet_number:<8} | {result.hosts_needed:<10} | {result.total_ips:<8} | "
            f"{str(result.jump_width):<15} | {str(result.network.network_address):<15} | "
            f"/{result.network.prefixlen:<4} | {str(result.network.netmask):<15} | "
            f"{host_range:<25} | {str(result.network.broadcast_address):<15} | "
            f"{result.efficiency:.1f}%{'':<6}"
        )

    def export_results(self, filename: str) -> bool:
        """
        Exportiert alle VLSM-Ergebnisse in eine JSON-Datei
        Verwendet UTF-8 Encoding für korrekte Darstellung
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # JSON mit Einrückung für bessere Lesbarkeit exportieren
                json.dump(self._solve_history, f, indent=2, ensure_ascii=False)
            logger.info(f"VLSM-Ergebnisse erfolgreich exportiert nach: {filename}")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Exportieren der VLSM-Ergebnisse: {e}")
            return False

    def get_solve_history(self) -> List[Dict[str, Union[str, List[Dict]]]]:
        """
        Gibt eine Kopie der Lösungs-Historie zurück
        Verhindert unbeabsichtigte Änderungen an der internen Historie
        """
        return self._solve_history.copy()


# EQUAL SUBNETTING SOLVER CLASS
# ///////////////////////////////////////////////////////////////
class EqualSubnettingSolver(SubnettingSolver):
    """
    Klasse für gleich große Subnetze mit erweiterten Features
    Erstellt eine bestimmte Anzahl von Subnetzen mit identischer Größe
    """

    def __init__(self, calculator: SubnettingCalculator):
        """Initialisiert Equal-Solver mit Calculator und leerer Historie"""
        super().__init__(calculator)
        # Historie aller gelösten Equal-Subnetting-Aufgaben
        self._solve_history: List[Dict[str, Union[str, int, List[Dict]]]] = []

    def solve(self, network_str: str, num_subnets: int, exercise_name: str = "") -> Optional[
        List[ipaddress.IPv4Network]]:
        """
        Löst Aufgaben mit gleich großen Subnetzen
        Berechnet optimale Subnetzgröße basierend auf gewünschter Anzahl
        """
        logger.info(f"Löse Equal-Subnetting-Aufgabe: {exercise_name or 'Unbenannt'}")

        try:
            # IPv4Network-Objekt aus String erstellen
            network: ipaddress.IPv4Network = ipaddress.IPv4Network(network_str, strict=False)
        except ipaddress.AddressValueError as e:
            logger.error(f"Ungültiges IPv4-Netzwerk: {e}")
            print("Ungültiges IPv4-Netzwerk!")
            return None

        # Header ausgeben
        self._print_header(network, num_subnets, exercise_name)

        # Neue Prefix-Länge berechnen basierend auf gewünschter Subnetz-Anzahl
        subnet_bits: int = self.calculator.calculate_subnet_bits(num_subnets)
        new_prefix: int = network.prefixlen + subnet_bits

        # Prüfung ob zu viele Subnetze angefordert wurden
        if new_prefix > 30:
            logger.warning("Zu viele Subnetze angefordert")
            print("Fehler: Zu viele Subnetze!")
            return None

        # Subnetze erstellen basierend auf neuer Prefix-Länge
        subnets: List[ipaddress.IPv4Network] = list(network.subnets(new_prefix=new_prefix))
        # Host-Bits für Sprungweiten-Berechnung
        host_bits: int = 32 - new_prefix
        # Sprungweite zwischen Subnetzen
        jump_width: int = 2 ** host_bits

        # Subnetz-Tabelle ausgeben
        self._print_subnets(subnets, new_prefix, jump_width)

        # Effizienz-Statistiken berechnen und ausgeben
        requested_subnets = min(num_subnets, len(subnets))
        total_available_hosts = requested_subnets * (jump_width - 2)  # -2 für Netz und Broadcast
        efficiency = (requested_subnets * (jump_width - 2)) / network.num_addresses * 100

        print(f"\nEffizienz-Statistiken:")
        print(f"  Angeforderte Subnetze: {num_subnets}")
        print(f"  Erstelle Subnetze: {len(subnets)}")
        print(f"  Hosts pro Subnetz: {jump_width - 2}")
        print(f"  Gesamt nutzbare Hosts: {total_available_hosts}")
        print(f"  Netzwerk-Effizienz: {efficiency:.2f}%")

        # Ergebnis in Historie speichern
        solve_data = {
            'network': network_str,
            'exercise_name': exercise_name,
            'num_subnets': num_subnets,
            'created_subnets': len(subnets),
            'hosts_per_subnet': jump_width - 2,
            'efficiency': efficiency,
            # Nur erste 4 Subnetze speichern um JSON-Größe zu begrenzen
            'subnets': [{'network': str(subnet), 'cidr': subnet.prefixlen} for subnet in subnets[:4]]
        }
        self._solve_history.append(solve_data)

        return subnets

    def _print_header(self, network: ipaddress.IPv4Network, num_subnets: int, exercise_name: str) -> None:
        """Druckt den Header der Equal-Subnetting-Ausgabe mit allen relevanten Informationen"""
        print(f"\n{'=' * 80}")
        if exercise_name:
            print(f"Aufgabe: {exercise_name}")
        print(f"Ausgangsnetz: {network}")
        print(f"Subnetzmaske: {network.netmask}")
        print(f"Subnetting-Ziel: {num_subnets} gleichgroße Netze")
        print(f"{'=' * 80}")

    def _print_subnets(self, subnets: List[ipaddress.IPv4Network], new_prefix: int, jump_width: int) -> None:
        """
        Druckt die Subnetz-Tabelle mit allen relevanten Informationen
        Zeigt nur die ersten 4 Subnetze für bessere Übersicht
        """
        # Tabellenkopf mit Host-Anzahl-Spalte
        print(f"{'':12} | {'Subnetz-ID':<15} | {'CIDR':<5} | {'Host-IP-Range':<30} | {'Broadcast':<15} | {'Hosts':<6}")
        print("-" * 95)

        # Zeige erste 4 Subnetze oder alle wenn weniger als 4 vorhanden
        max_show: int = min(4, len(subnets))
        for i in range(max_show):
            subnet: ipaddress.IPv4Network = subnets[i]
            # Erste und letzte verwendbare Host-IP berechnen
            first_host: ipaddress.IPv4Address = subnet.network_address + 1
            last_host: ipaddress.IPv4Address = subnet.broadcast_address - 1
            # Host-Range als String formatieren
            host_range: str = f"{str(first_host)} bis {str(last_host)}"
            # Anzahl verwendbarer Hosts (-2 für Netz- und Broadcast-Adresse)
            host_count: int = subnet.num_addresses - 2

            # Formatierte Tabellenzeile ausgeben
            print(
                f"Subnetz {i + 1}:   | {str(subnet.network_address):<15} | /{new_prefix:<4} | "
                f"{host_range:<30} | {str(subnet.broadcast_address):<15} | {host_count:<6}"
            )

        # Hinweis wenn mehr Subnetze vorhanden als angezeigt
        if len(subnets) > 4:
            print("...")

        # Sprungweite in separater Zeile anzeigen
        print(f"Sprungweite: | {jump_width:<15} | {'':5} | {'':30} | {'':15} | {'':6}")

    def get_solve_history(self) -> List[Dict[str, Union[str, int, List[Dict]]]]:
        """
        Gibt eine Kopie der Equal-Subnetting-Historie zurück
        Verhindert unbeabsichtigte Änderungen an der internen Historie
        """
        return self._solve_history.copy()

    def export_results(self, filename: str) -> bool:
        """
        Exportiert alle Equal-Subnetting-Ergebnisse in eine JSON-Datei
        Verwendet UTF-8 Encoding für korrekte Darstellung
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # JSON mit Einrückung für bessere Lesbarkeit exportieren
                json.dump(self._solve_history, f, indent=2, ensure_ascii=False)
            logger.info(f"Equal-Subnetting-Ergebnisse erfolgreich exportiert nach: {filename}")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Exportieren der Equal-Subnetting-Ergebnisse: {e}")
            return False


# CONFIGURATION MANAGER CLASS
# ///////////////////////////////////////////////////////////////
class ConfigurationManager:
    """
    Klasse für persistentes Konfigurationsmanagement
    Lädt und speichert Einstellungen in JSON-Format
    """

    def __init__(self, config_file: str = "ip_analyzer_config.json"):
        """Initialisiert Configuration Manager mit Standard-Konfigurationsdatei"""
        self.config_file = Path(config_file)
        # Standard-Konfigurationswerte definieren
        self.default_config = {
            'export_directory': './exports',  # Standard Export-Verzeichnis
            'max_history_entries': 100,  # Maximale Anzahl Historie-Einträge
            'show_efficiency': True,  # Effizienz in Tabellen anzeigen
            'decimal_places': 2,  # Dezimalstellen für Berechnungen
            'table_width': 135,  # Breite der Ausgabetabellen
            'logging_level': 'INFO'  # Standard Logging-Level
        }
        # Konfiguration laden oder Standard-Werte verwenden
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Union[str, int, bool]]:
        """
        Lädt die Konfiguration aus der JSON-Datei
        Erstellt Standard-Konfiguration wenn Datei nicht existiert
        """
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                # Geladene Konfiguration mit Standard-Werten zusammenführen
                # Standard-Werte als Basis nehmen
                merged_config = self.default_config.copy()
                # Mit geladenen Werten überschreiben
                merged_config.update(config)
                return merged_config
            except Exception as e:
                logger.warning(f"Fehler beim Laden der Konfiguration: {e}, verwende Defaults")
                return self.default_config.copy()
        else:
            # Datei existiert nicht, Standard-Konfiguration erstellen und speichern
            self._save_config(self.default_config)
            return self.default_config.copy()

    def _save_config(self, config: Dict[str, Union[str, int, bool]]) -> None:
        """
        Speichert die Konfiguration in die JSON-Datei
        Erstellt Verzeichnis falls nicht vorhanden
        """
        try:
            # Parent-Verzeichnis erstellen falls nicht vorhanden
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                # JSON mit Einrückung für bessere Lesbarkeit speichern
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Fehler beim Speichern der Konfiguration: {e}")

    def get(self, key: str, default=None) -> Union[str, int, bool, None]:
        """
        Holt einen Konfigurationswert basierend auf dem Schlüssel
        Gibt default-Wert zurück wenn Schlüssel nicht existiert
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Union[str, int, bool]) -> None:
        """
        Setzt einen Konfigurationswert und speichert die Konfiguration
        Automatische Persistierung bei jeder Änderung
        """
        self.config[key] = value
        # Konfiguration sofort speichern
        self._save_config(self.config)

    def reset_to_defaults(self) -> None:
        """
        Setzt die Konfiguration auf Standardwerte zurück
        Überschreibt alle benutzerdefinierten Einstellungen
        """
        self.config = self.default_config.copy()
        self._save_config(self.config)


# PREDEFINED EXERCISES CLASS
# ///////////////////////////////////////////////////////////////
class PredefinedExercises:
    """
    Sammlung von vordefinierten Übungsaufgaben für Subnetting
    Kombiniert VLSM- und Equal-Subnetting-Aufgaben
    """

    def __init__(self, vlsm_solver: VLSMSolver, equal_solver: EqualSubnettingSolver):
        """Initialisiert mit Referenzen zu beiden Solver-Typen"""
        self.vlsm_solver = vlsm_solver
        self.equal_solver = equal_solver

    def run_all(self) -> None:
        """
        Führt alle vordefinierten Übungsaufgaben nacheinander aus
        Kombiniert verschiedene Schwierigkeitsgrade und Aufgabentypen
        """
        # Aufgaben-Liste mit Netzwerk, Anforderungen, Name und Typ definieren
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

        # Alle Aufgaben nacheinander ausführen
        for network, requirements, name, exercise_type in exercises:
            if exercise_type == "equal":
                # Equal-Subnetting-Aufgabe lösen
                self.equal_solver.solve(network, requirements, name)
            else:
                # VLSM-Aufgabe lösen
                self.vlsm_solver.solve(network, requirements, name)


# USER INTERFACE CLASS
# ///////////////////////////////////////////////////////////////
class UserInterface:
    """
    Erweiterte Benutzeroberfläche mit Konfiguration und Export-Features
    Hauptklasse für die Interaktion mit dem Benutzer
    """

    def __init__(self):
        """Initialisiert alle Komponenten des IP-Analyzers"""
        # Konfigurationsverwaltung initialisieren
        self.config = ConfigurationManager()
        # Grundlegende Berechnungsklasse
        self.calculator = SubnettingCalculator()
        # IPv6-Analyzer mit Historie
        self.ipv6_analyzer = IPv6Analyzer()
        # VLSM-Solver für variable Subnetzgrößen
        self.vlsm_solver = VLSMSolver(self.calculator)
        # Equal-Solver für gleich große Subnetze
        self.equal_solver = EqualSubnettingSolver(self.calculator)
        # Vordefinierte Übungsaufgaben
        self.exercises = PredefinedExercises(self.vlsm_solver, self.equal_solver)

        # Export-Verzeichnis aus Konfiguration erstellen
        export_dir = Path(self.config.get('export_directory', './exports'))
        export_dir.mkdir(parents=True, exist_ok=True)

        # Logging-Level aus Konfiguration setzen
        log_level = self.config.get('logging_level', 'INFO')
        logging.getLogger().setLevel(getattr(logging, log_level))

    def run(self) -> None:
        """
        Hauptschleife der Anwendung
        Zeigt Menü an und verarbeitet Benutzereingaben
        """
        self._print_welcome()

        # Unendliche Schleife bis Benutzer beendet
        while True:
            choice: str = input("Wählen Sie eine Option 0-9: ").strip()

            # Pattern Matching für Menü-Optionen
            match choice:
                case '0':
                    # Anwendung beenden
                    self._handle_exit()
                    break
                case '1':
                    # IPv6-Analyse
                    self._handle_ipv6_analysis()
                case '2':
                    # VLSM-Aufgabe
                    self._handle_vlsm_task()
                case '3':
                    # Gleiche Subnetze
                    self._handle_equal_subnets()
                case '4':
                    # Vordefinierte Übungsaufgaben
                    self._handle_predefined_exercises()
                case '5':
                    # Benutzerdefinierte VLSM-Aufgabe
                    self._handle_custom_vlsm_task()
                case '6':
                    # Schnelle VLSM-Eingabe
                    self._handle_quick_vlsm_input()
                case '7':
                    # Export-Menü
                    self._handle_export_menu()
                case '8':
                    # Historie anzeigen
                    self._handle_history_menu()
                case '9':
                    # Einstellungen
                    self._handle_settings_menu()
                case _:
                    # Ungültige Eingabe
                    print("Ungültige Option!")

            # Trennlinie nach jeder Aktion
            print("\n" + "=" * 80)

    def _print_welcome(self) -> None:
        """
        Druckt die erweiterte Willkommensnachricht mit allen verfügbaren Optionen
        Unterscheidet zwischen Haupt- und erweiterten Funktionen
        """
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
        """
        Behandelt das ordnungsgemäße Beenden der Anwendung
        Loggt das Beenden für Debugging-Zwecke
        """
        print("Auf Wiedersehen!")
        logger.info("Anwendung beendet")

    def _handle_ipv6_analysis(self) -> None:
        """
        Behandelt IPv6-Analyse mit optionalem Export
        Bietet nach der Analyse Export-Option an
        """
        print("\n--- IPv6-Analyse ---")
        # Benutzer-Eingabe für IPv6-Adresse
        ipv6_input: str = input("IPv6‑Adresse (Hex oder Binär): ").strip()
        # Analyse durchführen
        result = self.ipv6_analyzer.analyze(ipv6_input)

        # Wenn Analyse erfolgreich war, Export anbieten
        if result:
            export_choice = input("\nMöchten Sie das Ergebnis exportieren? (j/n): ").strip().lower()
            if export_choice in ['j', 'ja', 'y', 'yes']:
                # Dateiname eingeben oder Standard verwenden
                filename = input(
                    "Dateiname (ohne .json): ").strip() or f"ipv6_analysis_{len(self.ipv6_analyzer.get_analysis_history())}"
                # Vollständigen Pfad erstellen
                export_path = Path(self.config.get('export_directory')) / f"{filename}.json"
                # Export durchführen
                if self.ipv6_analyzer.export_history(str(export_path)):
                    print(f"✓ Ergebnis exportiert nach: {export_path}")

    def _handle_vlsm_task(self) -> None:
        """
        Behandelt manuelle VLSM-Aufgaben-Eingabe
        Benutzer gibt Netzwerk und Host-Liste ein
        """
        print("\n--- VLSM-Aufgabe lösen ---")
        # Ausgangsnetzwerk eingeben
        network: str = input("Ausgangsnetz (z.B. 192.174.2.0/23): ").strip()
        # Host-Anforderungen als kommagetrennte Liste eingeben
        hosts_str: str = input("Benötigte Hosts pro Subnetz (getrennt durch Komma): ").strip()

        try:
            # String zu Integer-Liste konvertieren
            hosts_list: List[int] = [int(x.strip()) for x in hosts_str.split(',')]
            # VLSM-Aufgabe lösen
            self.vlsm_solver.solve(network, hosts_list)
        except ValueError:
            # Fehlerbehandlung bei ungültiger Eingabe
            self._print_invalid_input()

    def _handle_equal_subnets(self) -> None:
        """
        Behandelt Equal-Subnetting-Aufgaben
        Benutzer gibt Netzwerk und gewünschte Anzahl Subnetze ein
        """
        print("\n--- Gleiche Subnetze ---")
        # Ausgangsnetzwerk eingeben
        network: str = input("Ausgangsnetz (z.B. 120.50.16.0/20): ").strip()

        try:
            # Anzahl der gewünschten Subnetze eingeben
            num_subnets: int = int(input("Anzahl gleicher Subnetze: "))
            # Equal-Subnetting-Aufgabe lösen
            self.equal_solver.solve(network, num_subnets)
        except ValueError:
            # Fehlerbehandlung bei ungültiger Eingabe
            self._print_invalid_input()

    def _handle_predefined_exercises(self) -> None:
        """
        Behandelt die Ausführung aller vordefinierten Übungsaufgaben
        Führt automatisch alle 8 Standardaufgaben aus
        """
        print("\n--- Alle Übungsaufgaben ---")
        # Alle vordefinierten Aufgaben ausführen
        self.exercises.run_all()

    def _handle_custom_vlsm_task(self) -> None:
        """
        Behandelt die Erstellung benutzerdefinierter VLSM-Aufgaben
        Interaktiver Wizard für Netzwerk und Host-Anforderungen
        """
        print("\n--- Benutzerdefinierte VLSM-Aufgabe ---")

        # Schritt 1: Ausgangsnetz eingeben und validieren
        network: Optional[ipaddress.IPv4Network] = self._get_network_input()
        if network is None:
            return

        # Schritt 2: Anzahl der Subnetze eingeben
        num_subnets: Optional[int] = self._get_subnet_count()
        if num_subnets is None:
            return

        # Schritt 3: Host-Anforderungen für jedes Subnetz eingeben
        hosts_requirements: Optional[List[int]] = self._get_host_requirements(num_subnets)
        if hosts_requirements is None:
            return

        # Schritt 4: Zusammenfassung anzeigen und Bestätigung einholen
        if self._confirm_vlsm_task(network, num_subnets, hosts_requirements):
            # VLSM-Aufgabe mit benutzerdefinierten Parametern lösen
            self.vlsm_solver.solve(
                str(network),
                hosts_requirements,
                f"Benutzerdefinierte Aufgabe ({num_subnets} Subnetze)"
            )
        else:
            print("Berechnung abgebrochen.")

    def _handle_quick_vlsm_input(self) -> None:
        """
        Behandelt schnelle VLSM-Eingabe in einer Zeile
        Format: "Netz-ID/CIDR Host1,Host2,Host3,..."
        """
        print("\n--- Schnelle VLSM-Eingabe ---")
        print("Format: Netz-ID/CIDR Hosts1,Hosts2,Hosts3,...")
        print("Beispiel: 192.168.0.0/24 50,30,20,10")

        # Eingabe in einer Zeile
        input_line: str = input("Eingabe: ").strip()

        try:
            # String in Netzwerk und Host-Liste aufteilen
            parts: List[str] = input_line.split(' ', 1)
            if len(parts) != 2:
                print("Ungültiges Format! Verwenden Sie: Netz-ID/CIDR Hosts1,Hosts2,...")
                return

            network_str, hosts_str = parts
            # Host-Liste parsen
            hosts_list: List[int] = [int(x.strip()) for x in hosts_str.split(',')]

            # Netzwerk validieren
            ipaddress.IPv4Network(network_str, strict=False)

            # VLSM-Aufgabe lösen
            self.vlsm_solver.solve(network_str, hosts_list, "Schnelle VLSM-Eingabe")

        except (ValueError, ipaddress.AddressValueError) as e:
            print(f"Ungültige Eingabe: {e}")

    def _handle_export_menu(self) -> None:
        """
        Behandelt das Export-Menü mit verschiedenen Export-Optionen
        Ermöglicht selektiven oder kompletten Datenexport
        """
        print("\n--- Export-Menü ---")
        print("[1] VLSM-Ergebnisse exportieren")
        print("[2] Equal-Subnetting-Ergebnisse exportieren")
        print("[3] IPv6-Analyse-Historie exportieren")
        print("[4] Alle Daten exportieren")
        print("[0] Zurück")

        choice = input("Wählen Sie eine Option: ").strip()
        # Export-Verzeichnis aus Konfiguration laden
        export_dir = Path(self.config.get('export_directory'))

        # Export-Option basierend auf Benutzer-Wahl
        match choice:
            case '1':
                # Nur VLSM-Ergebnisse exportieren
                filename = export_dir / "vlsm_results.json"
                if self.vlsm_solver.export_results(str(filename)):
                    print(f"✓ VLSM-Ergebnisse exportiert nach: {filename}")
            case '2':
                # Nur Equal-Subnetting-Ergebnisse exportieren
                filename = export_dir / "equal_subnetting_results.json"
                if self.equal_solver.export_results(str(filename)):
                    print(f"✓ Equal-Subnetting-Ergebnisse exportiert nach: {filename}")
            case '3':
                # Nur IPv6-Analyse-Historie exportieren
                filename = export_dir / "ipv6_analysis_history.json"
                if self.ipv6_analyzer.export_history(str(filename)):
                    print(f"✓ IPv6-Analyse-Historie exportiert nach: {filename}")
            case '4':
                # Alle Daten in separate Dateien exportieren
                self._export_all_data(export_dir)
            case '0':
                # Zurück zum Hauptmenü
                return
            case _:
                print("Ungültige Option!")

    def _export_all_data(self, export_dir: Path) -> None:
        """
        Exportiert alle verfügbaren Daten in separate JSON-Dateien
        Zeigt Erfolgsstatistik an
        """
        success_count = 0
        total_exports = 3

        # VLSM-Ergebnisse exportieren
        if self.vlsm_solver.export_results(str(export_dir / "vlsm_results.json")):
            success_count += 1

        # Equal-Subnetting-Ergebnisse exportieren
        if self.equal_solver.export_results(str(export_dir / "equal_subnetting_results.json")):
            success_count += 1

        # IPv6-Analyse-Historie exportieren
        if self.ipv6_analyzer.export_history(str(export_dir / "ipv6_analysis_history.json")):
            success_count += 1

        # Erfolgsmeldung mit Statistik
        print(f"✓ {success_count}/{total_exports} Exporte erfolgreich nach: {export_dir}")

    def _handle_history_menu(self) -> None:
        """
        Behandelt das Historie-Menü mit verschiedenen Historie-Ansichten
        Zeigt die letzten Aktionen der verschiedenen Funktionen an
        """
        print("\n--- Historie-Menü ---")
        print("[1] VLSM-Lösungs-Historie anzeigen")
        print("[2] Equal-Subnetting-Historie anzeigen")
        print("[3] IPv6-Analyse-Historie anzeigen")
        print("[0] Zurück")

        choice = input("Wählen Sie eine Option: ").strip()

        # Historie-Ansicht basierend auf Benutzer-Wahl
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
        """
        Zeigt die VLSM-Lösungs-Historie an
        Beschränkt auf die letzten 5 Einträge für bessere Übersicht
        """
        history = self.vlsm_solver.get_solve_history()
        if not history:
            print("Keine VLSM-Historie vorhanden.")
            return

        print(f"\n--- VLSM-Historie ({len(history)} Einträge) ---")
        # Nur die letzten 5 Einträge anzeigen
        for i, entry in enumerate(history[-5:], 1):
            print(f"{i}. {entry.get('exercise_name', 'Unbenannt')} - Netz: {entry['network']}")
            # Effizienz-Information anzeigen falls verfügbar
            if 'statistics' in entry:
                print(f"   Effizienz: {entry['statistics']['efficiency']:.2f}%")

    def _show_equal_history(self) -> None:
        """
        Zeigt die Equal-Subnetting-Historie an
        Beschränkt auf die letzten 5 Einträge für bessere Übersicht
        """
        history = self.equal_solver.get_solve_history()
        if not history:
            print("Keine Equal-Subnetting-Historie vorhanden.")
            return

        print(f"\n--- Equal-Subnetting-Historie ({len(history)} Einträge) ---")
        # Nur die letzten 5 Einträge anzeigen
        for i, entry in enumerate(history[-5:], 1):
            print(f"{i}. {entry.get('exercise_name', 'Unbenannt')} - Netz: {entry['network']}")
            print(f"   Subnetze: {entry['created_subnets']}, Effizienz: {entry['efficiency']:.2f}%")

    def _show_ipv6_history(self) -> None:
        """
        Zeigt die IPv6-Analyse-Historie an
        Beschränkt auf die letzten 5 Einträge für bessere Übersicht
        """
        history = self.ipv6_analyzer.get_analysis_history()
        if not history:
            print("Keine IPv6-Analyse-Historie vorhanden.")
            return

        print(f"\n--- IPv6-Analyse-Historie ({len(history)} Einträge) ---")
        # Nur die letzten 5 Einträge anzeigen
        for i, entry in enumerate(history[-5:], 1):
            print(f"{i}. Original: {entry['original']}")
            print(f"   Komprimiert: {entry['compressed']}")

    def _handle_settings_menu(self) -> None:
        """
        Behandelt das Einstellungsmenü mit verschiedenen Konfigurationsoptionen
        Ermöglicht Anzeige und Änderung aller verfügbaren Einstellungen
        """
        print("\n--- Einstellungen ---")
        print("[1] Aktuelle Einstellungen anzeigen")
        print("[2] Export-Verzeichnis ändern")
        print("[3] Maximale Historie-Einträge ändern")
        print("[4] Logging-Level ändern")
        print("[5] Auf Standardwerte zurücksetzen")
        print("[0] Zurück")

        choice = input("Wählen Sie eine Option: ").strip()

        # Einstellungs-Option basierend auf Benutzer-Wahl
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
        """
        Zeigt alle aktuellen Konfigurationseinstellungen an
        Formatiert als Schlüssel-Wert-Paare
        """
        print("\n--- Aktuelle Einstellungen ---")
        for key, value in self.config.config.items():
            print(f"{key}: {value}")

    def _change_export_directory(self) -> None:
        """
        Ändert das Export-Verzeichnis nach Benutzer-Eingabe
        Erstellt das Verzeichnis automatisch falls es nicht existiert
        """
        current = self.config.get('export_directory')
        print(f"Aktuelles Export-Verzeichnis: {current}")
        new_dir = input("Neues Export-Verzeichnis: ").strip()
        if new_dir:
            # Verzeichnis erstellen falls es nicht existiert
            Path(new_dir).mkdir(parents=True, exist_ok=True)
            # Neue Konfiguration speichern
            self.config.set('export_directory', new_dir)
            print(f"✓ Export-Verzeichnis geändert zu: {new_dir}")

    def _change_max_history(self) -> None:
        """
        Ändert die maximale Anzahl Historie-Einträge
        Validiert Eingabe auf positive Ganzzahl
        """
        current = self.config.get('max_history_entries')
        print(f"Aktuelle max. Historie-Einträge: {current}")
        try:
            new_max = int(input("Neue maximale Anzahl: ").strip())
            if new_max > 0:
                # Neue Konfiguration speichern
                self.config.set('max_history_entries', new_max)
                print(f"✓ Maximale Historie-Einträge geändert zu: {new_max}")
            else:
                print("Wert muss größer als 0 sein!")
        except ValueError:
            print("Ungültige Eingabe!")

    def _change_logging_level(self) -> None:
        """
        Ändert das Logging-Level aus vordefinierten Optionen
        Setzt das Level sofort im laufenden Logger
        """
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        current = self.config.get('logging_level')
        print(f"Aktuelles Logging-Level: {current}")
        print("Verfügbare Level:", ', '.join(levels))
        new_level = input("Neues Logging-Level: ").strip().upper()
        if new_level in levels:
            # Neue Konfiguration speichern
            self.config.set('logging_level', new_level)
            # Logging-Level sofort ändern
            logging.getLogger().setLevel(getattr(logging, new_level))
            print(f"✓ Logging-Level geändert zu: {new_level}")
        else:
            print("Ungültiges Logging-Level!")

    def _reset_settings(self) -> None:
        """
        Setzt alle Einstellungen auf Standardwerte zurück
        Erfordert Benutzerbestätigung wegen irreversiblen Änderungen
        """
        confirm = input("Möchten Sie wirklich alle Einstellungen zurücksetzen? (j/n): ").strip().lower()
        if confirm in ['j', 'ja', 'y', 'yes']:
            # Alle Einstellungen zurücksetzen
            self.config.reset_to_defaults()
            print("✓ Einstellungen auf Standardwerte zurückgesetzt")

    def _get_network_input(self) -> Optional[ipaddress.IPv4Network]:
        """
        Interaktive Eingabe und Validierung eines IPv4-Netzwerks
        Wiederholt Eingabe bis gültiges Netzwerk eingegeben wurde
        """
        while True:
            network_input: str = input("Ausgangsnetz mit CIDR (z.B. 192.168.0.0/24): ").strip()
            try:
                # IPv4Network-Objekt erstellen und validieren
                network: ipaddress.IPv4Network = ipaddress.IPv4Network(network_input, strict=False)
                # Bestätigungsinfo ausgeben
                print(f"✓ Ausgangsnetz: {network}")
                print(f"  Verfügbare IPs: {network.num_addresses}")
                print(f"  Verfügbare Hosts: {network.num_addresses - 2}")
                return network
            except ipaddress.AddressValueError:
                print("Ungültiges Netzwerk! Format: IP/CIDR (z.B. 192.168.0.0/24)")

    def _get_subnet_count(self) -> Optional[int]:
        """
        Interaktive Eingabe und Validierung der Subnetz-Anzahl
        Wiederholt Eingabe bis gültige positive Ganzzahl eingegeben wurde
        """
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
        """
        Interaktive Eingabe der Host-Anforderungen für jedes Subnetz
        Validiert jede Eingabe auf positive Ganzzahl
        """
        print(f"\nGeben Sie die Host-Anforderungen für {num_subnets} Subnetze ein:")
        hosts_requirements: List[int] = []

        # Für jedes Subnetz Host-Anzahl eingeben
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
        """
        Zeigt Zusammenfassung der VLSM-Aufgabe und holt Benutzerbestätigung
        Berechnet und zeigt Ressourcenverbrauch und mögliche Probleme an
        """
        print(f"\n--- Zusammenfassung ---")
        print(f"Ausgangsnetz: {network}")
        print(f"Anzahl Subnetze: {num_subnets}")
        print("Host-Anforderungen:")

        total_required_hosts: int = 0
        # Für jede Host-Anforderung tatsächlich benötigte IPs berechnen
        for i, hosts in enumerate(hosts_requirements, 1):
            print(f"  Subnetz {i:2d}: {hosts:4d} Hosts")
            # Tatsächlich benötigte IPs (nächste Potenz von 2)
            required_ips: int = 2 ** self.calculator.calculate_host_bits(hosts)
            total_required_hosts += required_ips

        # Ressourcenvergleich
        print(f"\nBenötigte IPs gesamt: {total_required_hosts}")
        print(f"Verfügbare IPs:       {network.num_addresses}")

        # Warnung bei Ressourcenknappheit
        if total_required_hosts > network.num_addresses:
            print("WARNUNG: Nicht genügend IP-Adressen verfügbar!")
            print("Möglicherweise können nicht alle Subnetze erstellt werden.")
        else:
            print("Genügend IP-Adressen verfügbar")

        # Benutzerbestätigung einholen
        proceed: str = input("\nMöchten Sie die VLSM-Berechnung durchführen? (j/n): ").strip().lower()
        return proceed in ['j', 'ja', 'y', 'yes']

    def _print_invalid_input(self) -> None:
        """
        Standardisierte Fehlermeldung für ungültige Benutzereingaben
        Wird konsistent in der gesamten Anwendung verwendet
        """
        print("Ungültige Eingabe! Bitte versuchen Sie es erneut.")


# MAIN FUNCTION
# ///////////////////////////////////////////////////////////////
def main() -> None:
    """
    Hauptfunktion der Anwendung
    Erstellt UserInterface-Instanz und startet die Hauptschleife
    """
    try:
        # Benutzeroberfläche initialisieren
        ui = UserInterface()
        # Hauptschleife starten
        ui.run()
    except KeyboardInterrupt:
        # Graceful handling von Ctrl+C
        print("\n\nAnwendung durch Benutzer unterbrochen.")
        logger.info("Anwendung durch Keyboard Interrupt beendet")
    except Exception as e:
        # Unerwartete Fehler abfangen und loggen
        logger.error(f"Unerwarteter Fehler in main(): {e}")
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")


# PROGRAM ENTRY POINT
# ///////////////////////////////////////////////////////////////
if __name__ == "__main__":
    # Anwendung nur starten wenn direkt ausgeführt (nicht importiert)
    main()
