"""YAML schema, loader, and serializer for ewscan configurations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ewscan.contracts import EmitterInfo, EpisodeConfig


class ConfigError(Exception):
    """Raised when a configuration file or dictionary is malformed or invalid."""


def config_from_dict(data: dict[str, Any]) -> EpisodeConfig:
    """Convert and validate a raw dictionary into an EpisodeConfig instance."""
    if not isinstance(data, dict):
        raise ConfigError(f"Configuration data must be a dictionary, got {type(data).__name__}")

    # Check required fields
    required_fields = ["n_bands", "n_slots", "k", "detection_threshold", "pfa"]
    missing = [field for field in required_fields if field not in data]
    if missing:
        raise ConfigError(f"Missing required configuration fields: {', '.join(missing)}")

    # Validate types and value constraints for scalar fields
    n_bands = data["n_bands"]
    if not isinstance(n_bands, int) or isinstance(n_bands, bool) or n_bands <= 0:
        raise ConfigError(f"'n_bands' must be a positive integer, got {n_bands!r}")

    n_slots = data["n_slots"]
    if not isinstance(n_slots, int) or isinstance(n_slots, bool) or n_slots <= 0:
        raise ConfigError(f"'n_slots' must be a positive integer, got {n_slots!r}")

    k = data["k"]
    if not isinstance(k, int) or isinstance(k, bool) or k <= 0:
        raise ConfigError(f"'k' must be a positive integer, got {k!r}")
    if k > n_bands:
        raise ConfigError(f"'k' ({k}) cannot exceed 'n_bands' ({n_bands})")

    pfa = data["pfa"]
    if not isinstance(pfa, (int, float)) or isinstance(pfa, bool):
        raise ConfigError(f"'pfa' must be a number between 0.0 and 1.0, got {pfa!r}")
    pfa = float(pfa)
    if not (0.0 <= pfa <= 1.0):
        raise ConfigError(f"'pfa' must be between 0.0 and 1.0, got {pfa}")

    detection_threshold = data["detection_threshold"]
    if not isinstance(detection_threshold, (int, float)) or isinstance(detection_threshold, bool):
        raise ConfigError(f"'detection_threshold' must be a number, got {detection_threshold!r}")
    detection_threshold = float(detection_threshold)

    seed = data.get("seed", 0)
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ConfigError(f"'seed' must be an integer, got {seed!r}")

    retune_cost_slots = data.get("retune_cost_slots", 0)
    if (
        not isinstance(retune_cost_slots, int)
        or isinstance(retune_cost_slots, bool)
        or retune_cost_slots < 0
    ):
        raise ConfigError(
            f"'retune_cost_slots' must be a non-negative integer, got {retune_cost_slots!r}"
        )

    # Process emitters
    raw_emitters = data.get("emitters", [])
    if not isinstance(raw_emitters, (list, tuple)):
        raise ConfigError(f"'emitters' must be a list of emitter objects, got {type(raw_emitters).__name__}")

    emitters_list: list[EmitterInfo] = []
    for idx, em in enumerate(raw_emitters):
        if not isinstance(em, dict):
            raise ConfigError(f"Emitter at index {idx} must be a dictionary, got {type(em).__name__}")

        em_required = ["band", "snr", "threat_level", "emitter_type"]
        em_missing = [f for f in em_required if f not in em]
        if em_missing:
            raise ConfigError(f"Emitter at index {idx} missing fields: {', '.join(em_missing)}")

        band = em["band"]
        if not isinstance(band, int) or isinstance(band, bool) or not (0 <= band < n_bands):
            raise ConfigError(f"Emitter at index {idx} 'band' must be an integer in range [0, {n_bands - 1}], got {band!r}")

        snr = em["snr"]
        if not isinstance(snr, (int, float)) or isinstance(snr, bool):
            raise ConfigError(f"Emitter at index {idx} 'snr' must be a number, got {snr!r}")

        threat_level = em["threat_level"]
        if not isinstance(threat_level, (int, float)) or isinstance(threat_level, bool) or threat_level < 0:
            raise ConfigError(f"Emitter at index {idx} 'threat_level' must be a non-negative number, got {threat_level!r}")

        emitter_type = em["emitter_type"]
        if not isinstance(emitter_type, str) or not emitter_type.strip():
            raise ConfigError(f"Emitter at index {idx} 'emitter_type' must be a non-empty string, got {emitter_type!r}")

        params = em.get("params", {})
        if not isinstance(params, dict):
            raise ConfigError(f"Emitter at index {idx} 'params' must be a dictionary, got {type(params).__name__}")

        emitters_list.append(
            EmitterInfo(
                band=band,
                snr=float(snr),
                threat_level=float(threat_level),
                emitter_type=emitter_type,
                params=params,
            )
        )

    return EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=k,
        emitters=tuple(emitters_list),
        detection_threshold=detection_threshold,
        pfa=pfa,
        seed=seed,
        retune_cost_slots=retune_cost_slots,
    )


def config_to_dict(config: EpisodeConfig) -> dict[str, Any]:
    """Convert an EpisodeConfig instance into a dictionary suitable for YAML serialization."""
    if not isinstance(config, EpisodeConfig):
        raise TypeError(f"Expected EpisodeConfig instance, got {type(config).__name__}")

    return {
        "n_bands": config.n_bands,
        "n_slots": config.n_slots,
        "k": config.k,
        "detection_threshold": config.detection_threshold,
        "pfa": config.pfa,
        "seed": config.seed,
        "retune_cost_slots": config.retune_cost_slots,
        "emitters": [
            {
                "band": em.band,
                "snr": em.snr,
                "threat_level": em.threat_level,
                "emitter_type": em.emitter_type,
                "params": dict(em.params),
            }
            for em in config.emitters
        ],
    }


def load_config_from_yaml(yaml_content: str) -> EpisodeConfig:
    """Parse a YAML string and return a validated EpisodeConfig instance."""
    if not isinstance(yaml_content, str):
        raise ConfigError(f"YAML content must be a string, got {type(yaml_content).__name__}")

    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML content: {exc}") from exc

    if data is None:
        raise ConfigError("YAML content is empty")

    return config_from_dict(data)


def load_config(file_path: str | Path) -> EpisodeConfig:
    """Load and validate an EpisodeConfig from a YAML file."""
    path = Path(file_path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise ConfigError(f"Error reading config file {path}: {exc}") from exc

    return load_config_from_yaml(content)


def dump_config(config: EpisodeConfig, file_path: str | Path | None = None) -> str:
    """Serialize an EpisodeConfig to YAML format. Write to file_path if provided."""
    data = config_to_dict(config)
    yaml_str = yaml.safe_dump(data, sort_keys=False)

    if file_path is not None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml_str, encoding="utf-8")

    return yaml_str
