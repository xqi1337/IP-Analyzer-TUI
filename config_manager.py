# ///////////////////////////////////////////////////////////////
#
# PROJECT: IP-Analyzer TUI
# BY: xqi
# V: 1.0.0
#
# Konfigurationsverwaltung für persistente Einstellungen
# Lädt und speichert Benutzereinstellungen in JSON-Format
#
# ///////////////////////////////////////////////////////////////


# IMPORTS
# ///////////////////////////////////////////////////////////////
import json
import logging
from pathlib import Path
from typing import Dict, Union

# LOGGING
# ///////////////////////////////////////////////////////////////
logger = logging.getLogger(__name__)


# MAIN CLASS
# ///////////////////////////////////////////////////////////////
class ConfigurationManager:
    """
    Klasse für persistentes Konfigurationsmanagement
    Lädt und speichert Einstellungen in JSON-Format
    """

    def __init__(self, config_file: str = "ip_analyzer_config.json"):
        # INITIALIZE CONFIG MANAGER
        self.config_file = Path(config_file)
        
        # DEFAULT CONFIGURATION VALUES
        self.default_config = {
            'export_directory': './exports',
            'max_history_entries': 100,
            'show_efficiency': True,
            'decimal_places': 2,
            'table_width': 135,
            'logging_level': 'INFO'
        }
        
        # LOAD CONFIGURATION
        self.config = self._load_config()


    # CONFIGURATION LOADING
    # ///////////////////////////////////////////////////////////////
    def _load_config(self) -> Dict[str, Union[str, int, bool]]:
        """Lädt die Konfiguration aus der JSON-Datei"""
        if self.config_file.exists():
            try:
                # READ CONFIG FILE
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # MERGE WITH DEFAULTS
                merged_config = self.default_config.copy()
                merged_config.update(config)
                return merged_config
            except Exception as e:
                # FALLBACK TO DEFAULTS
                logger.warning(f"Fehler beim Laden der Konfiguration: {e}, verwende Defaults")
                return self.default_config.copy()
        else:
            # CREATE DEFAULT CONFIG FILE
            self._save_config(self.default_config)
            return self.default_config.copy()


    # CONFIGURATION SAVING
    # ///////////////////////////////////////////////////////////////
    def _save_config(self, config: Dict[str, Union[str, int, bool]]) -> None:
        """Speichert die Konfiguration in die JSON-Datei"""
        try:
            # ENSURE DIRECTORY EXISTS
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # WRITE CONFIG TO FILE
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            # LOG ERROR ON SAVE FAILURE
            logger.error(f"Fehler beim Speichern der Konfiguration: {e}")


    # CONFIGURATION ACCESS
    # ///////////////////////////////////////////////////////////////
    def get(self, key: str, default=None) -> Union[str, int, bool, None]:
        """Holt einen Konfigurationswert basierend auf dem Schlüssel"""
        # RETURN CONFIG VALUE OR DEFAULT
        return self.config.get(key, default)

    def set(self, key: str, value: Union[str, int, bool]) -> None:
        """Setzt einen Konfigurationswert und speichert die Konfiguration"""
        # UPDATE CONFIG VALUE
        self.config[key] = value
        # PERSIST CHANGES
        self._save_config(self.config)


    # CONFIGURATION RESET
    # ///////////////////////////////////////////////////////////////
    def reset_to_defaults(self) -> None:
        """Setzt die Konfiguration auf Standardwerte zurück"""
        # RESET TO DEFAULT VALUES
        self.config = self.default_config.copy()
        # SAVE RESET CONFIGURATION
        self._save_config(self.config)
