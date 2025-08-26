"""
IP-Analyzer (Hex/Binär) mit Subnetting Berechnungen - Hauptprogramm
- VLSM-Aufgaben mit benutzerdefinierten Host-Anforderungen
- Gleich große Subnetze
- IPv6-Adressanalyse
- Export/Import und Konfiguration
"""

import logging
from user_interface import UserInterface

# Logging-Konfiguration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def main() -> None:
    """
    Hauptfunktion der Anwendung
    Erstellt UserInterface-Instanz und startet die Hauptschleife
    """
    try:
        ui = UserInterface()
        ui.run()
    except KeyboardInterrupt:
        print("\n\nAnwendung durch Benutzer unterbrochen.")
        logger.info("Anwendung durch Keyboard Interrupt beendet")
    except Exception as e:
        logger.error(f"Unerwarteter Fehler in main(): {e}")
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")


if __name__ == "__main__":
    main()