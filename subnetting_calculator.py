# ///////////////////////////////////////////////////////////////
#
# Grundlegende Subnetting-Berechnungen
# PROJECT: IP-Analyzer TUI
# BY: xqi
# V: 1.0.0
#
# ///////////////////////////////////////////////////////////////


# IMPORTS
# ///////////////////////////////////////////////////////////////
import math
from typing import Protocol, List, Optional, Union
from abc import ABC, abstractmethod
from core_types import JumpWidth, OctetType, SubnetResult
import ipaddress


# PROTOCOLS
# ///////////////////////////////////////////////////////////////
class NetworkAnalyzer(Protocol):
    """
    Protocol (Interface) für Network-Analyzer Klassen
    Definiert die erforderliche analyze-Methode
    """

    def analyze(self, address: str) -> None:
        """Analysiert eine Netzwerk-Adresse"""
        ...


# ABSTRACT BASE CLASSES
# ///////////////////////////////////////////////////////////////
class SubnettingSolver(ABC):
    """
    Abstrakte Basisklasse für alle Subnetting-Solver
    Definiert gemeinsame Eigenschaften und abstrakte Methoden
    """

    def __init__(self, calculator: 'SubnettingCalculator'):
        # STORE CALCULATOR REFERENCE
        self.calculator = calculator

    @abstractmethod
    def solve(self, network_str: str, *args, **kwargs) -> Optional[
        Union[List[SubnetResult], List[ipaddress.IPv4Network]]]:
        """
        Abstrakte Methode zum Lösen von Subnetting-Problemen
        Muss von allen Unterklassen implementiert werden
        """
        pass


# MAIN CALCULATOR CLASS
# ///////////////////////////////////////////////////////////////
class SubnettingCalculator:
    """
    Klasse für grundlegende Subnetting-Berechnungen
    Enthält statische Methoden für mathematische Operationen
    """

    # SUBNET CALCULATION
    # ///////////////////////////////////////////////////////////////
    @staticmethod
    def calculate_subnet_bits(num_subnets: int) -> int:
        """Berechnet benötigte Subnetz-Bits für eine feste Anzahl von Subnetzen"""
        # FORMULA: 2^bits >= num_subnets
        return math.ceil(math.log2(num_subnets))

    # HOST CALCULATION
    # ///////////////////////////////////////////////////////////////
    @staticmethod
    def calculate_host_bits(num_hosts: int) -> int:
        """Berechnet die benötigten Host-Bits für eine feste Anzahl von Hosts"""
        # ADD 2 FOR NETWORK AND BROADCAST ADDRESS
        return math.ceil(math.log2(num_hosts + 2))

    # JUMP WIDTH CALCULATION
    # ///////////////////////////////////////////////////////////////
    @staticmethod
    def calculate_jump_width(host_bits: int) -> JumpWidth:
        """
        Berechnet Sprungweite und bestimmt betroffene Oktette
        Basierend auf der Anzahl der Host-Bits
        """
        # CALCULATE TOTAL IPs
        total_ips: int = 2 ** host_bits

        # DETERMINE AFFECTED OCTET BASED ON HOST BITS
        if host_bits <= 8:  # AFFECTS 4TH OCTET ONLY
            return JumpWidth(total_ips, OctetType.FOURTH)
        elif host_bits <= 16:  # AFFECTS 3RD AND 4TH OCTET
            jump_3rd: int = total_ips // 256
            return JumpWidth(jump_3rd, OctetType.THIRD)
        elif host_bits <= 24:  # AFFECTS 2ND, 3RD AND 4TH OCTET
            jump_2nd: int = total_ips // (256 * 256)
            return JumpWidth(jump_2nd, OctetType.SECOND)
        else:  # AFFECTS ALL OCTETS
            jump_1st: int = total_ips // (256 * 256 * 256)
            return JumpWidth(jump_1st, OctetType.FIRST)