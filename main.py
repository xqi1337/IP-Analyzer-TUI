# ///////////////////////////////////////////////////////////////
#
# BY: xqi
# PROJECT: IP-Analyzer TUI  
# V: 1.0.0
#
# IP-Analyzer (Hex/Binär) mit Subnetting Berechnungen
# - VLSM-Aufgaben mit benutzerdefinierten Host-Anforderungen
# - Gleich große Subnetze
# - Vordefinierte Übungsaufgaben
#
# HAUPTFUNKTIONEN:
# - IPv6-Adressanalyse mit Hex/Binär-Konvertierung
# - VLSM (Variable Length Subnet Masking) Berechnungen
# - Equal Subnetting für gleich große Subnetze
# - Export/Import von Ergebnissen
# - Historie-Verwaltung und Konfiguration
#
# ///////////////////////////////////////////////////////////////

# IMPORTS
# ///////////////////////////////////////////////////////////////
import logging
from user_interface import UserInterface

# LOGGING SETUP
# ///////////////////////////////////////////////////////////////
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# MAIN FUNCTION
# ///////////////////////////////////////////////////////////////
def main() -> None:
    """
    Erstellt UserInterface-Instanz
    """
    try:
        # CREATE USER INTERFACE
        ui = UserInterface()
        # START APPLICATION
        ui.run()
    except KeyboardInterrupt:
        # HANDLE USER INTERRUPTION
        print("\n\nAnwendung durch Benutzer unterbrochen.")
        logger.info("Anwendung durch Keyboard Interrupt beendet")
    except Exception as e:
        # HANDLE UNEXPECTED ERRORS
        logger.error(f"Unerwarteter Fehler in main(): {e}")
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")


# APPLICATION ENTRY POINT
# ///////////////////////////////////////////////////////////////
if __name__ == "__main__":
    main()
