"""
IP-Analyzer (Hex/Binär) mit Subnetting Berechnungen
- VLSM-Aufgaben mit benutzerdefinierten Host-Anforderungen
- Gleich große Subnetze
- Vordefinierte Übungsaufgaben
"""
import ipaddress
import math



def block_role(index: int) -> str:
    if index < 3:
        return "Global Routing Prefix"
    elif index == 3:
        return "Subnetz‑ID"
    else:
        return "Interface Identifier"


def hex_to_bin(hex_block: str) -> str:
    return bin(int(hex_block, 16))[2:].zfill(16)


def bin_to_hex(bin_block: str) -> str:
    return hex(int(bin_block, 2))[2:].zfill(4)


def is_binary_ipv6(addr: str) -> bool:
    addr_clean = addr.split('/')[0]
    allowed_chars = set('01:')
    return all(c in allowed_chars for c in addr_clean)


def convert_binary_to_hex_ipv6(binary_addr: str) -> str:
    addr_parts = binary_addr.split('/')
    addr_clean = addr_parts[0]

    binary_blocks = addr_clean.split(':')

    hex_blocks = []
    for block in binary_blocks:
        if len(block) == 16:
            hex_blocks.append(bin_to_hex(block))
        elif len(block) == 0:
            hex_blocks.append('')
        else:
            padded_block = block.zfill(16)
            hex_blocks.append(bin_to_hex(padded_block))

    hex_addr = ':'.join(hex_blocks)

    if len(addr_parts) > 1:
        hex_addr += '/' + addr_parts[1]

    return hex_addr


def analyze_ipv6(addr: str) -> None:
    original_input = addr

    if is_binary_ipv6(addr):
        print(f"Binäre Eingabe erkannt: {addr}")
        try:
            addr = convert_binary_to_hex_ipv6(addr)
            print(f"Konvertiert zu Hex:     {addr}")
        except ValueError as e:
            print(f"Fehler beim Konvertieren der binären Eingabe: {e}")
            return

    try:
        addr_without_cidr = addr.split('/')[0]
        ip = ipaddress.IPv6Address(addr_without_cidr)
    except ipaddress.AddressValueError:
        print("Ungültige IPv6‑Adresse!")
        return

    expanded = ip.exploded
    compressed = ip.compressed

    print(f"IPv6‑Adresse Eingabe:   {original_input}")
    if is_binary_ipv6(original_input):
        print(f"Konvertiert zu Hex:     {addr}")
    print(f"Ausgeschrieben:         {expanded}")
    print(f"Kurzschreibweise:       {compressed}\n")

    blocks = expanded.split(":")
    for i, block in enumerate(blocks):
        role = block_role(i)
        print(f"Block {i + 1}: {block.upper()}  | {hex_to_bin(block)}  → {role}")


def calculate_subnet_bits(num_subnets: int) -> int:
    """Berechnet benötigte Subnetz-Bits für feste Anzahl von SN"""
    return math.ceil(math.log2(num_subnets))


def calculate_host_bits(num_hosts: int) -> int:
    """Berechnet die benötigten Host-Bits für feste Anzahl von Hosts"""
    return math.ceil(math.log2(num_hosts + 2))


def calculate_jump_width(host_bits: int) -> tuple:
    """Berechnet Sprungweite und betroffene Oktette"""
    total_ips = 2 ** host_bits

    if host_bits <= 8:
        # Sprungweite nur im 4. Oktett
        return total_ips, "4. Oktett"
    elif host_bits <= 16:
        # Sprungweite im 3. und 4. Oktett
        jump_3rd = total_ips // 256
        return jump_3rd, "3. Oktett"
    elif host_bits <= 24:
        # Sprungweite im 2. und nachfolgenden Oktetten
        jump_2nd = total_ips // (256 * 256)
        return jump_2nd, "2. Oktett"
    else:
        # Sprungweite im 1. Oktett
        jump_1st = total_ips // (256 * 256 * 256)
        return jump_1st, "1. Oktett"


def solve_vlsm_exercise(network_str: str, host_requirements: list, exercise_name: str = "") -> None:
    """
    Löst VLSM-Aufgaben im gewünschten Tabellenformat
    host_requirements: Liste von benötigten Hosts pro Subnetz
    """
    try:
        network = ipaddress.IPv4Network(network_str, strict=False)
    except ipaddress.AddressValueError:
        print("Ungültiges IPv4-Netzwerk!")
        return

    print(f"\n{'=' * 80}")
    if exercise_name:
        print(f"Aufgabe: {exercise_name}")
    print(f"Ausgangsnetz: {network}")
    print(f"{'=' * 80}")

    # Sortiere Host-Anforderungen nach Größe (größte zuerst)
    sorted_requirements = sorted(enumerate(host_requirements, 1), key=lambda x: x[1], reverse=True)

    # Tabellenkopf
    print(
        f"{'Subnetz':<8} | {'Benötigte':<10} | {'IPs im':<8} | {'Sprungweite':<15} | {'Netz-ID':<15} | {'CIDR':<5} | {'Subnetzmaske':<15} | {'Host-IP-Range':<25} | {'Broadcast':<15}")
    print(
        f"{'':8} | {'Hosts':<10} | {'Subnetz':<8} | {'(+ Oktett)':<15} | {'':<15} | {'':<5} | {'Dezimal':<15} | {'':<25} | {'':<15}")
    print("-" * 120)

    current_network = network
    used_space = []

    for subnet_num, hosts_needed in sorted_requirements:
        # Berechne benötigte Host-Bits
        host_bits = calculate_host_bits(hosts_needed)
        subnet_prefix = 32 - host_bits
        total_ips = 2 ** host_bits

        # Berechne Sprungweite
        jump_width, octets = calculate_jump_width(host_bits)

        # Finde nächstes verfügbares Subnetz
        found_subnet = None

        # Generiere alle möglichen Subnetze der benötigten Größe
        for possible_net in network.subnets(new_prefix=subnet_prefix):
            # Prüfe, ob dieses Subnetz mit bereits verwendeten überschneidet
            overlaps = False
            for used_net in used_space:
                if possible_net.overlaps(used_net):
                    overlaps = True
                    break

            if not overlaps:
                found_subnet = possible_net
                used_space.append(found_subnet)
                break

        if found_subnet is None:
            print(f"Fehler: Kein Platz für Subnetz {subnet_num} mit {hosts_needed} Hosts")
            continue

        # Berechne Host-Range
        first_host = found_subnet.network_address + 1
        last_host = found_subnet.broadcast_address - 1
        host_range = f"{str(first_host)} - {str(last_host)}"

        # Formatiere Sprungweite-String
        if jump_width == total_ips:
            jump_str = f"{jump_width} ({octets})"
        else:
            jump_str = f"{jump_width} ({octets})"

        # Ausgabe der Zeile
        print(f"{subnet_num:<8} | {hosts_needed:<10} | {total_ips:<8} | {jump_str:<15} | "
              f"{str(found_subnet.network_address):<15} | /{subnet_prefix:<4} | "
              f"{str(found_subnet.netmask):<15} | {host_range:<25} | {str(found_subnet.broadcast_address):<15}")


def solve_equal_subnetting(network_str: str, num_subnets: int, exercise_name: str = "") -> None:
    """
    Löst Aufgaben mit gleich großen Subnetzen
    """
    try:
        network = ipaddress.IPv4Network(network_str, strict=False)
    except ipaddress.AddressValueError:
        print("Ungültiges IPv4-Netzwerk!")
        return

    print(f"\n{'=' * 80}")
    if exercise_name:
        print(f"Aufgabe: {exercise_name}")
    print(f"Ausgangsnetz: {network}")
    print(f"Subnetzmaske: {network.netmask}")
    print(f"Subnetting-Ziel: {num_subnets} gleichgroße Netze")
    print(f"{'=' * 80}")

    # Berechne neue Prefix-Länge
    subnet_bits = calculate_subnet_bits(num_subnets)
    new_prefix = network.prefixlen + subnet_bits

    if new_prefix > 30:
        print("Fehler: Zu viele Subnetze!")
        return

    # Erstelle Subnetze
    subnets = list(network.subnets(new_prefix=new_prefix))
    host_bits = 32 - new_prefix
    jump_width = 2 ** host_bits

    print(f"{'':12} | {'Subnetz-ID':<15} | {'CIDR':<5} | {'Host-IP-Range':<30} | {'Broadcast':<15}")
    print("-" * 85)

    # Zeige erste 4 Subnetze oder alle wenn weniger als 4
    max_show = min(4, len(subnets))
    for i in range(max_show):
        subnet = subnets[i]
        first_host = subnet.network_address + 1
        last_host = subnet.broadcast_address - 1
        host_range = f"{str(first_host)} bis {str(last_host)}"

        print(f"Subnetz {i + 1}:   | {str(subnet.network_address):<15} | /{new_prefix:<4} | "
              f"{host_range:<30} | {str(subnet.broadcast_address):<15}")

    if len(subnets) > 4:
        print("...")

    print(f"Sprungweite: | {jump_width:<15}")


def run_predefined_exercises():
    """Führt alle vordefinierten Übungsaufgaben aus"""

    # Aufgabe 1
    solve_equal_subnetting("120.50.16.0/20", 4, "Aufgabe 1")

    # Aufgabe 2
    solve_equal_subnetting("10.0.0.0/8", 4096, "Aufgabe 2")

    # Aufgabe 3
    solve_vlsm_exercise("192.174.2.0/23", [200, 120, 65], "Aufgabe 3")

    # Aufgabe 4
    solve_vlsm_exercise("172.16.0.0/18", [8000, 1600, 231, 8, 2], "Aufgabe 4")

    # Aufgabe 5
    solve_vlsm_exercise("10.0.192.0/20", [400, 250, 240, 88, 70, 40], "Aufgabe 5")

    # Aufgabe 6
    solve_vlsm_exercise("10.80.16.0/20", [250, 126, 70, 15], "Aufgabe 6")

    # Aufgabe 7
    solve_vlsm_exercise("192.168.4.0/22", [100, 79, 54, 22, 8], "Aufgabe 7")

    # Aufgabe 8
    solve_vlsm_exercise("10.16.76.0/22", [223, 44, 30], "Aufgabe 8")


def create_custom_vlsm_task():
    """
    Interaktive Funktion zum Erstellen einer benutzerdefinierten VLSM-Aufgabe
    """
    print("\n--- Benutzerdefinierte VLSM-Aufgabe ---")

    # Ausgangsnetz eingeben
    while True:
        network_input = input("Ausgangsnetz mit CIDR (z.B. 192.168.0.0/24): ").strip()
        try:
            network = ipaddress.IPv4Network(network_input, strict=False)
            print(f"✓ Ausgangsnetz: {network}")
            print(f"  Verfügbare IPs: {network.num_addresses}")
            print(f"  Verfügbare Hosts: {network.num_addresses - 2}")
            break
        except ipaddress.AddressValueError:
            print("Ungültiges Netzwerk! Format: IP/CIDR (z.B. 192.168.0.0/24)")

    # Anzahl der Subnetze eingeben
    while True:
        try:
            num_subnets = int(input("\nAnzahl der Subnetze: ").strip())
            if num_subnets <= 0:
                print("Anzahl muss größer als 0 sein!")
                continue
            break
        except ValueError:
            ungültige_eingabe_meldung()

    # Host-Anforderungen für jedes Subnetz eingeben
    print(f"\nGeben Sie die Host-Anforderungen für {num_subnets} Subnetze ein:")
    hosts_requirements = []

    for i in range(1, num_subnets + 1):
        while True:
            try:
                hosts = int(input(f"Subnetz {i:2d} - Benötigte Hosts: ").strip())
                if hosts <= 0:
                    print("Host-Anzahl muss größer als 0 sein!")
                    continue
                hosts_requirements.append(hosts)
                break
            except ValueError:
                ungültige_eingabe_meldung()

    # Zusammenfassung anzeigen
    print(f"\n--- Zusammenfassung ---")
    print(f"Ausgangsnetz: {network}")
    print(f"Anzahl Subnetze: {num_subnets}")
    print("Host-Anforderungen:")
    total_required_hosts = 0
    for i, hosts in enumerate(hosts_requirements, 1):
        print(f"  Subnetz {i:2d}: {hosts:4d} Hosts")
        # Berechne tatsächlich benötigte IPs (nächste Potenz von 2)
        required_ips = 2 ** calculate_host_bits(hosts)
        total_required_hosts += required_ips

    print(f"\nBenötigte IPs gesamt: {total_required_hosts}")
    print(f"Verfügbare IPs:       {network.num_addresses}")

    if total_required_hosts > network.num_addresses:
        print("WARNUNG: Nicht genügend IP-Adressen verfügbar!")
        print("Möglicherweise können nicht alle Subnetze erstellt werden.")
    else:
        print("Genügend IP-Adressen verfügbar")

    # Bestätigung
    proceed = input("\nMöchten Sie die VLSM-Berechnung durchführen? (j/n): ").strip().lower()
    if proceed in ['j', 'ja', 'y', 'yes']:
        solve_vlsm_exercise(str(network), hosts_requirements, f"Benutzerdefinierte Aufgabe ({num_subnets} Subnetze)")
    else:
        print("Berechnung abgebrochen.")


def ungültige_eingabe_meldung():
    print("Ungültige Eingabe! Bitte versuchen Sie es erneut.")


# -----------------------------------------------------------------------------
# MAIN PROGRAM
# -----------------------------------------------------------------------------
def main():
    print("=" * 80)
    print("         IP-Analyzer mit Subnetting-Aufgaben-Löser")
    print("=" * 80)
    print("Funktionen:")
    print("[0] Beenden")
    print("[1] IPv6-Analyse (Hex/Binär)")
    print("[2] VLSM-Aufgabe (Host-Liste eingeben)")
    print("[3] Gleiche Subnetze (Anzahl eingeben)")
    print("[4] Alle Übungsaufgaben lösen")
    print("[5] Benutzerdefinierte VLSM-Aufgabe erstellen")
    print("[6] Schnelle VLSM-Eingabe (Netz + Hosts)")
    print()

    while True:
        choice = input("Wählen Sie eine Option 0-6: ").strip()

        match choice:
            case '0':
                break

            case '1':
                print("\n--- IPv6-Analyse ---")
                ipv6_input = input("IPv6‑Adresse (Hex oder Binär): ").strip()
                analyze_ipv6(ipv6_input)

            case '2':
                print("\n--- VLSM-Aufgabe lösen ---")
                network = input("Ausgangsnetz (z.B. 192.174.2.0/23): ").strip()
                hosts_str = input("Benötigte Hosts pro Subnetz (getrennt durch Komma): ").strip()
                try:
                    hosts_list = [int(x.strip()) for x in hosts_str.split(',')]
                    solve_vlsm_exercise(network, hosts_list)
                except ValueError:
                    ungültige_eingabe_meldung()

            case '3':
                print("\n--- Gleiche Subnetze ---")
                network = input("Ausgangsnetz (z.B. 120.50.16.0/20): ").strip()
                try:
                    num_subnets = int(input("Anzahl gleicher Subnetze: "))
                    solve_equal_subnetting(network, num_subnets)
                except ValueError:
                    ungültige_eingabe_meldung()

            case '4':
                print("\n--- Alle Übungsaufgaben ---")
                run_predefined_exercises()

            case '5':
                create_custom_vlsm_task()

            case '6':
                print("\n--- Schnelle VLSM-Eingabe ---")
                print("Format: Netz-ID/CIDR Hosts1,Hosts2,Hosts3,...")
                print("Beispiel: 192.168.0.0/24 50,30,20,10")

                input_line = input("Eingabe: ").strip()
                try:
                    parts = input_line.split(' ', 1)
                    if len(parts) != 2:
                        print("Ungültiges Format! Verwenden Sie: Netz-ID/CIDR Hosts1,Hosts2,...")
                        continue

                    network_str = parts[0]
                    hosts_str = parts[1]
                    hosts_list = [int(x.strip()) for x in hosts_str.split(',')]

                    # Validiere Netzwerk
                    network = ipaddress.IPv4Network(network_str, strict=False)

                    solve_vlsm_exercise(network_str, hosts_list, "Schnelle VLSM-Eingabe")

                except (ValueError, ipaddress.AddressValueError) as e:
                    print(f"Ungültige Eingabe: {e}")
            case _:
                print("Ungültige Option!")

        print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
