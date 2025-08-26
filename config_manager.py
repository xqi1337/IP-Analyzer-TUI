"""
Konfigurationsverwaltung für persistente Einstellungen
"""

import json
import logging
from pathlib import Path
from typing import Dict, Union

logger = logging.getLogger(__name__)


class ConfigurationManager:
    """
    Klasse für persistentes Konfigurationsmanagement
    Lädt und speichert Einstellungen in JSON-Format
    """

    def __init__(self, config_file: str = "ip_analyzer_config.json"):
        self.config_file = Path(config_file)
        self.default_config = {
            'export_directory': './exports',
            'max_history_entries': 100,
            'show_efficiency': True,
            'decimal_places': 2,
            'table_width': 135,
            'logging_level': 'INFO'
        }
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Union[str, int, bool]]:
        """Lädt die Konfiguration aus der JSON-Datei"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                merged_config = self.default_config.copy()
                merged_config.update(config)
                return merged_config
            except Exception as e:
                logger.warning(f"Fehler beim Laden der Konfiguration: {e}, verwende Defaults")
                return self.default_config.copy()
        else:
            self._save_config(self.default_config)
            return self.default_config.copy()

    def _save_config(self, config: Dict[str, Union[str, int, bool]]) -> None:
        """Speichert die Konfiguration in die JSON-Datei"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Fehler beim Speichern der Konfiguration: {e}")

    def get(self, key: str, default=None) -> Union[str, int, bool, None]:
        """Holt einen Konfigurationswert basierend auf dem Schlüssel"""
        return self.config.get(key, default)

    def set(self, key: str, value: Union[str, int, bool]) -> None:
        """Setzt einen Konfigurationswert und speichert die Konfiguration"""
        self.config[key] = value
        self._save_config(self.config)

    def reset_to_defaults(self) -> None:
        """Setzt die Konfiguration auf Standardwerte zurück"""
        self.config = self.default_config.copy()
        self._save_config(self.config)