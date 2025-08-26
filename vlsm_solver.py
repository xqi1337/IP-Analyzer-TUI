"""
VLSM (Variable Length Subnet Masking) Solver
"""

import ipaddress
import logging
import json
from typing import List, Tuple, Optional, Dict, Union
from core_types import SubnetResult, NetworkStatistics
from subnetting_calculator import SubnettingSolver

logger = logging.getLogger(__name__)


class VLSMSolver(SubnettingSolver):
    """
    Klasse für VLSM (Variable Length Subnet Masking) Aufgaben
    Erstellt Subnetze unterschiedlicher Größe basierend auf Host-Anforderungen
    """

    def __init__(self, calculator):
        super().__init__(calculator)
        self._solve_history: List[Dict[str, Union[str, List[Dict]]]] = []

    def solve(self, network_str: str, host_requirements: List[int], exercise_name: str = "") -> Optional[
        List[SubnetResult]]:
        """Löst VLSM-Aufgaben und gibt formatierte Tabelle aus"""
        logger.info(f"Löse VLSM-Aufgabe: {exercise_name or 'Unbenannt'}")

        try:
            network: ipaddress.IPv4Network = ipaddress.IPv4Network(network_str, strict=False)
        except ipaddress.AddressValueError as e:
            logger.error(f"Ungültiges IPv4-Netzwerk: {e}")
            print("Ungültiges IPv4-Netzwerk!")
            return None

        self._print_header(network, exercise_name)
        self._print_table_header()

        # Sortiere nach Größe für optimale Platznutzung
        sorted_requirements: List[Tuple[int, int]] = sorted(
            enumerate(host_requirements, 1),
            key=lambda x: x[1],
            reverse=True
        )

        used_space: List[ipaddress.IPv4Network] = []
        results: List[SubnetResult] = []

        for subnet_num, hosts_needed in sorted_requirements:
            subnet_result = self._calculate_subnet(
                network, subnet_num, hosts_needed, used_space
            )

            if subnet_result is None:
                error_msg = f"Fehler: Kein Platz für Subnetz {subnet_num} mit {hosts_needed} Hosts"
                logger.warning(error_msg)
                print(error_msg)
                continue

            results.append(subnet_result)
            self._print_subnet_row(subnet_result)

        if results:
            stats = self._calculate_statistics(network, results)
            print(f"\n{stats}")

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
        """Berechnet ein einzelnes Subnetz basierend auf Host-Anforderungen"""
        host_bits: int = self.calculator.calculate_host_bits(hosts_needed)
        subnet_prefix: int = 32 - host_bits
        total_ips: int = 2 ** host_bits
        jump_width = self.calculator.calculate_jump_width(host_bits)

        for possible_net in base_network.subnets(new_prefix=subnet_prefix):
            if not any(possible_net.overlaps(used_net) for used_net in used_space):
                used_space.append(possible_net)

                first_host: ipaddress.IPv4Address = possible_net.network_address + 1
                last_host: ipaddress.IPv4Address = possible_net.broadcast_address - 1

                return SubnetResult(
                    subnet_number=subnet_num,
                    hosts_needed=hosts_needed,
                    total_ips=total_ips,
                    network=possible_net,
                    jump_width=jump_width,
                    first_host=first_host,
                    last_host=last_host
                )

        return None

    def _calculate_statistics(self, base_network: ipaddress.IPv4Network,
                              results: List[SubnetResult]) -> NetworkStatistics:
        """Berechnet Netzwerk-Statistiken basierend auf den Subnetz-Ergebnissen"""
        total_networks = len(results)
        total_hosts_available = sum(result.total_ips - 2 for result in results)
        total_hosts_used = sum(result.hosts_needed for result in results)
        overall_efficiency = (total_hosts_used / total_hosts_available) * 100 if total_hosts_available > 0 else 0
        unused_networks = base_network.num_addresses - sum(result.total_ips for result in results)

        return NetworkStatistics(
            total_networks=total_networks,
            total_hosts_available=total_hosts_available,
            total_hosts_used=total_hosts_used,
            overall_efficiency=overall_efficiency,
            unused_networks=unused_networks
        )

    def _print_header(self, network: ipaddress.IPv4Network, exercise_name: str) -> None:
        """Druckt den Header der VLSM-Ausgabe"""
        print(f"\n{'=' * 80}")
        if exercise_name:
            print(f"Aufgabe: {exercise_name}")
        print(f"Ausgangsnetz: {network}")
        print(f"{'=' * 80}")

    def _print_table_header(self) -> None:
        """Druckt den formatierten Tabellenkopf"""
        print(
            f"{'Subnetz':<8} | {'Benötigte':<10} | {'IPs im':<8} | {'Sprungweite':<15} | "
            f"{'Netz-ID':<15} | {'CIDR':<5} | {'Subnetzmaske':<15} | "
            f"{'Host-IP-Range':<30} | {'Broadcast':<15} | {'Effizienz':<10}"
        )
        print(
            f"{'':8} | {'Hosts':<10} | {'Subnetz':<8} | {'(+ Oktett)':<15} | "
            f"{'':<15} | {'':<5} | {'Dezimal':<15} | {'':<30} | {'':<15} | {'%':<10}"
        )
        print("-" * 135)

    def _print_subnet_row(self, result: SubnetResult) -> None:
        """Druckt eine formatierte Zeile der Subnetz-Tabelle"""
        host_range: str = f"{str(result.first_host)} - {str(result.last_host)}"

        print(
            f"{result.subnet_number:<8} | {result.hosts_needed:<10} | {result.total_ips:<8} | "
            f"{str(result.jump_width):<15} | {str(result.network.network_address):<15} | "
            f"/{result.network.prefixlen:<4} | {str(result.network.netmask):<15} | "
            f"{host_range:<30} | {str(result.network.broadcast_address):<15} | "
            f"{result.efficiency:.1f}%{'':<6}"
        )

    def export_results(self, filename: str) -> bool:
        """Exportiert alle VLSM-Ergebnisse in eine JSON-Datei"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self._solve_history, f, indent=2, ensure_ascii=False)
            logger.info(f"VLSM-Ergebnisse erfolgreich exportiert nach: {filename}")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Exportieren der VLSM-Ergebnisse: {e}")
            return False

    def get_solve_history(self) -> List[Dict[str, Union[str, List[Dict]]]]:
        """Gibt eine Kopie der Lösungs-Historie zurück"""
        return self._solve_history.copy()