"""
Grundlegende Datentypen und Enumerationen für den IP-Analyzer
"""

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Union, List


class IPv6BlockRole(Enum):
    """
    IPv6-Block-Rollen für bessere Klassifizierung der Adressteile
    Jeder Block einer IPv6-Adresse hat eine spezielle Funktion
    """
    GLOBAL_ROUTING_PREFIX = "Global Routing Prefix"
    SUBNET_ID = "Subnetz‑ID"
    INTERFACE_IDENTIFIER = "Interface Identifier"


class OctetType(Enum):
    """
    Oktett-Typen für Sprungweiten-Berechnung bei IPv4-Subnetting
    Definiert welches Oktett bei der Subnetz-Berechnung betroffen ist
    """
    FIRST = "1. Oktett"
    SECOND = "2. Oktett"
    THIRD = "3. Oktett"
    FOURTH = "4. Oktett"


@dataclass
class JumpWidth:
    """
    Sprungweite-Information für Subnetting-Berechnungen
    Enthält die Sprungweite und das betroffene Oktett
    """
    width: int
    affected_octet: OctetType

    def __str__(self) -> str:
        return f"{self.width} ({self.affected_octet.value})"


@dataclass
class SubnetResult:
    """
    Ergebnis einer Subnetz-Berechnung mit allen relevanten Informationen
    Wird für VLSM-Berechnungen verwendet und kann exportiert werden
    """
    subnet_number: int
    hosts_needed: int
    total_ips: int
    network: ipaddress.IPv4Network
    jump_width: JumpWidth
    first_host: ipaddress.IPv4Address
    last_host: ipaddress.IPv4Address
    efficiency: float = field(init=False)

    def __post_init__(self) -> None:
        """
        Wird nach der Initialisierung automatisch aufgerufen
        Berechnet die Effizienz des Subnetzes (verwendete vs. verfügbare Hosts)
        """
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
            'network_address': str(self.network.network_address),
            'cidr': self.network.prefixlen,
            'netmask': str(self.network.netmask),
            'first_host': str(self.first_host),
            'last_host': str(self.last_host),
            'broadcast': str(self.network.broadcast_address),
            'efficiency_percent': round(self.efficiency, 2),
            'jump_width': self.jump_width.width,
            'affected_octet': self.jump_width.affected_octet.value
        }


@dataclass
class NetworkStatistics:
    """
    Statistiken für ein Netzwerk nach der Subnetz-Berechnung
    Zeigt Gesamteffizienz und Ressourcenverbrauch an
    """
    total_networks: int
    total_hosts_available: int
    total_hosts_used: int
    overall_efficiency: float
    unused_networks: int

    def __str__(self) -> str:
        return (
            f"Netzwerk-Statistiken:\n"
            f"  Gesamte Subnetze: {self.total_networks}\n"
            f"  Verfügbare Hosts: {self.total_hosts_available}\n"
            f"  Verwendete Hosts: {self.total_hosts_used}\n"
            f"  Gesamteffizienz: {self.overall_efficiency:.2f}%\n"
            f"  Ungenutzte Hosts: {self.total_hosts_available - self.total_hosts_used}"
        )