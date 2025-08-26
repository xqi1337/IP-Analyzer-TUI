"""
Grundlegende Subnetting-Berechnungen
"""

import math
from typing import Protocol, List, Optional, Union
from abc import ABC, abstractmethod
from core_types import JumpWidth, OctetType, SubnetResult
import ipaddress


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
        self.calculator = calculator

    @abstractmethod
    def solve(self, network_str: str, *args, **kwargs) -> Optional[
        Union[List[SubnetResult], List[ipaddress.IPv4Network]]]:
        """
        Abstrakte Methode zum Lösen von Subnetting-Problemen
        Muss von allen Unterklassen implementiert werden
        """
        pass


class SubnettingCalculator:
    """
    Klasse für grundlegende Subnetting-Berechnungen
    Enthält statische Methoden für mathematische Operationen
    """

    @staticmethod
    def calculate_subnet_bits(num_subnets: int) -> int:
        """Berechnet benötigte Subnetz-Bits für eine feste Anzahl von Subnetzen"""
        return math.ceil(math.log2(num_subnets))

    @staticmethod
    def calculate_host_bits(num_hosts: int) -> int:
        """Berechnet die benötigten Host-Bits für eine feste Anzahl von Hosts"""
        return math.ceil(math.log2(num_hosts + 2))

    @staticmethod
    def calculate_jump_width(host_bits: int) -> JumpWidth:
        """
        Berechnet Sprungweite und bestimmt betroffene Oktette
        Basierend auf der Anzahl der Host-Bits
        """
        total_ips: int = 2 ** host_bits

        if host_bits <= 8:
            return JumpWidth(total_ips, OctetType.FOURTH)
        elif host_bits <= 16:
            jump_3rd: int = total_ips // 256
            return JumpWidth(jump_3rd, OctetType.THIRD)
        elif host_bits <= 24:
            jump_2nd: int = total_ips // (256 * 256)
            return JumpWidth(jump_2nd, OctetType.SECOND)
        else:
            jump_1st: int = total_ips // (256 * 256 * 256)
            return JumpWidth(jump_1st, OctetType.FIRST)