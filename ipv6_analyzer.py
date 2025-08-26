"""
IPv6-Adressanalyse mit Hex- und Binärkonvertierung
"""

import ipaddress
import logging
import json
from typing import Dict, Optional, List
from core_types import IPv6BlockRole

logger = logging.getLogger(__name__)


class IPv6Analyzer:
    """
    Klasse für IPv6-Adress-Analyse mit erweiterten Features
    Unterstützt Hex- und Binär-Format, Historie und Export
    """

    def __init__(self):
        self._analysis_history: List[Dict[str, str]] = []

    @staticmethod
    def get_block_role(index: int) -> IPv6BlockRole:
        """
        Bestimmt die Rolle eines IPv6-Blocks basierend auf dem Index (0-7)
        IPv6 besteht aus 8 Blöcken zu je 16 Bit
        """
        if index < 3:
            return IPv6BlockRole.GLOBAL_ROUTING_PREFIX
        elif index == 3:
            return IPv6BlockRole.SUBNET_ID
        else:
            return IPv6BlockRole.INTERFACE_IDENTIFIER

    @staticmethod
    def hex_to_binary(hex_block: str) -> str:
        """Konvertiert einen 4-stelligen Hex-Block zu 16-Bit Binär"""
        try:
            return bin(int(hex_block, 16))[2:].zfill(16)
        except ValueError as e:
            logger.error(f"Fehler bei Hex-zu-Binär Konvertierung: {e}")
            raise

    @staticmethod
    def binary_to_hex(binary_block: str) -> str:
        """Konvertiert einen 16-Bit Binär-Block zu 4-stelligem Hex"""
        try:
            return hex(int(binary_block, 2))[2:].upper().zfill(4)
        except ValueError as e:
            logger.error(f"Fehler bei Binär-zu-Hex Konvertierung: {e}")
            raise

    @staticmethod
    def is_binary_ipv6(address: str) -> bool:
        """Prüft ob eine IPv6-Adresse in binärer Notation vorliegt"""
        address_clean: str = address.split('/')[0]
        allowed_chars: set[str] = {'0', '1', ':'}
        return all(char in allowed_chars for char in address_clean)

    @classmethod
    def convert_binary_to_hex_ipv6(cls, binary_address: str) -> str:
        """Konvertiert eine binäre IPv6-Adresse zu Hex-Format"""
        address_parts: List[str] = binary_address.split('/')
        address_clean: str = address_parts[0]

        binary_blocks: List[str] = address_clean.split(':')
        hex_blocks: List[str] = []

        for block in binary_blocks:
            if len(block) == 16:
                hex_blocks.append(cls.binary_to_hex(block))
            elif len(block) == 0:
                hex_blocks.append('')
            else:
                padded_block: str = block.zfill(16)
                hex_blocks.append(cls.binary_to_hex(padded_block))

        hex_address: str = ':'.join(hex_blocks)

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
            if self.is_binary_ipv6(address):
                print(f"Binäre Eingabe erkannt: {address}")
                address = self.convert_binary_to_hex_ipv6(address)
                print(f"Konvertiert zu Hex:     {address}")

            address_without_cidr: str = address.split('/')[0]
            ip: ipaddress.IPv6Address = ipaddress.IPv6Address(address_without_cidr)

            expanded: str = ip.exploded
            compressed: str = ip.compressed

            analysis_result = {
                'original': original_input,
                'hex_format': address if not self.is_binary_ipv6(original_input) else address,
                'expanded': expanded,
                'compressed': compressed
            }

            self._analysis_history.append(analysis_result)

            print(f"IPv6‑Adresse Eingabe:   {original_input}")
            if self.is_binary_ipv6(original_input):
                print(f"Konvertiert zu Hex:     {address}")
            print(f"Ausgeschrieben:         {expanded}")
            print(f"Kurzschreibweise:       {compressed}\n")

            blocks: List[str] = expanded.split(":")
            for i, block in enumerate(blocks):
                role: IPv6BlockRole = self.get_block_role(i)
                binary: str = self.hex_to_binary(block)
                print(f"Block {i + 1}: {block.upper()}  | {binary}  → {role.value}")

            return analysis_result

        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"Fehler bei IPv6-Analyse: {e}")
            print(f"Ungültige IPv6‑Adresse: {e}")
            return None

    def get_analysis_history(self) -> List[Dict[str, str]]:
        """Gibt eine Kopie der Analyse-Historie zurück"""
        return self._analysis_history.copy()

    def export_history(self, filename: str) -> bool:
        """Exportiert die Analyse-Historie in eine JSON-Datei"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self._analysis_history, f, indent=2, ensure_ascii=False)
            logger.info(f"Historie erfolgreich exportiert nach: {filename}")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Exportieren der Historie: {e}")
            return False