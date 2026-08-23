"""Tests for ewscan.config — 1A.4 verification.

Verify criterion (PLAN.md 1A.4):
    Malformed config raises a named error (ConfigError); valid config round-trips.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import pytest

from ewscan.config import (
    ConfigError,
    config_from_dict,
    config_to_dict,
    dump_config,
    load_config,
    load_config_from_yaml,
)
from ewscan.contracts import EmitterInfo, EpisodeConfig


# ---------------------------------------------------------------------------
# Valid Configuration and Round-Trip Tests
# ---------------------------------------------------------------------------

class TestValidConfig:
    """Tests for loading, dict conversion, and round-tripping valid configs."""

    def test_config_from_dict_minimal(self):
        data = {
            "n_bands": 8,
            "n_slots": 1000,
            "k": 1,
            "detection_threshold": 2.5,
            "pfa": 1e-3,
        }
        cfg = config_from_dict(data)
        assert cfg.n_bands == 8
        assert cfg.n_slots == 1000
        assert cfg.k == 1
        assert cfg.detection_threshold == 2.5
        assert cfg.pfa == 1e-3
        assert cfg.seed == 0
        assert cfg.emitters == ()

    def test_config_from_dict_with_emitters(self):
        data = {
            "n_bands": 16,
            "n_slots": 2000,
            "k": 1,
            "detection_threshold": 3.0,
            "pfa": 1e-4,
            "seed": 42,
            "emitters": [
                {
                    "band": 2,
                    "snr": 12.5,
                    "threat_level": 0.9,
                    "emitter_type": "periodic",
                    "params": {"period": 20, "dwell": 2},
                }
            ],
        }
        cfg = config_from_dict(data)
        assert cfg.seed == 42
        assert len(cfg.emitters) == 1
        em = cfg.emitters[0]
        assert isinstance(em, EmitterInfo)
        assert em.band == 2
        assert em.snr == 12.5
        assert em.threat_level == 0.9
        assert em.emitter_type == "periodic"
        assert em.params == {"period": 20, "dwell": 2}

    def test_load_mvp_yaml(self):
        mvp_path = Path(__file__).parents[1] / "configs" / "mvp.yaml"
        cfg = load_config(mvp_path)
        assert cfg.n_bands == 16
        assert cfg.n_slots == 2000
        assert cfg.k == 1
        assert len(cfg.emitters) == 2

    def test_config_roundtrip_yaml_string(self):
        original = EpisodeConfig(
            n_bands=10,
            n_slots=500,
            k=1,
            emitters=(
                EmitterInfo(
                    band=1,
                    snr=18.0,
                    threat_level=1.0,
                    emitter_type="cw",
                    params={},
                ),
                EmitterInfo(
                    band=5,
                    snr=10.0,
                    threat_level=0.5,
                    emitter_type="gilbert_elliott",
                    params={"p01": 0.1, "p10": 0.3},
                ),
            ),
            detection_threshold=4.0,
            pfa=1e-5,
            seed=123,
        )
        yaml_str = dump_config(original)
        loaded = load_config_from_yaml(yaml_str)
        assert loaded == original

    def test_dump_and_load_file(self):
        original = EpisodeConfig(
            n_bands=4,
            n_slots=100,
            k=1,
            emitters=(),
            detection_threshold=2.0,
            pfa=0.01,
            seed=7,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test_config.yaml"
            dump_config(original, file_path)
            assert file_path.is_file()
            loaded = load_config(file_path)
            assert loaded == original

    def test_config_to_dict(self):
        cfg = EpisodeConfig(
            n_bands=4,
            n_slots=100,
            k=1,
            emitters=(
                EmitterInfo(band=0, snr=10.0, threat_level=0.5, emitter_type="test"),
            ),
            detection_threshold=2.0,
            pfa=0.01,
            seed=7,
        )
        d = config_to_dict(cfg)
        assert d["n_bands"] == 4
        assert d["emitters"][0]["band"] == 0
        with pytest.raises(TypeError):
            config_to_dict("not_a_config")  # type: ignore


# ---------------------------------------------------------------------------
# Malformed Configuration Error Tests
# ---------------------------------------------------------------------------

class TestMalformedConfig:
    """Tests that malformed YAML and invalid configurations raise ConfigError."""

    def test_nonexistent_file(self):
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config("nonexistent_file_path_12345.yaml")

    def test_invalid_yaml_syntax(self):
        bad_yaml = "n_bands: [unclosed list"
        with pytest.raises(ConfigError, match="Failed to parse YAML content"):
            load_config_from_yaml(bad_yaml)

    def test_empty_yaml(self):
        with pytest.raises(ConfigError, match="YAML content is empty"):
            load_config_from_yaml("")

    def test_non_dict_yaml(self):
        with pytest.raises(ConfigError, match="must be a dictionary"):
            load_config_from_yaml("- element1\n- element2")

    def test_non_string_yaml_input(self):
        with pytest.raises(ConfigError, match="YAML content must be a string"):
            load_config_from_yaml(12345)  # type: ignore

    def test_missing_required_fields(self):
        data = {"n_bands": 8, "n_slots": 1000}
        with pytest.raises(ConfigError, match="Missing required configuration fields"):
            config_from_dict(data)

    @pytest.mark.parametrize("bad_val", ["sixteen", -1, 0, True, 3.14])
    def test_invalid_n_bands(self, bad_val):
        data = {"n_bands": bad_val, "n_slots": 100, "k": 1, "detection_threshold": 2.0, "pfa": 0.01}
        with pytest.raises(ConfigError, match="'n_bands' must be a positive integer"):
            config_from_dict(data)

    @pytest.mark.parametrize("bad_val", ["hundred", -5, 0, True])
    def test_invalid_n_slots(self, bad_val):
        data = {"n_bands": 8, "n_slots": bad_val, "k": 1, "detection_threshold": 2.0, "pfa": 0.01}
        with pytest.raises(ConfigError, match="'n_slots' must be a positive integer"):
            config_from_dict(data)

    @pytest.mark.parametrize("bad_val", [0, -1, "one", True])
    def test_invalid_k_bounds(self, bad_val):
        data = {"n_bands": 8, "n_slots": 100, "k": bad_val, "detection_threshold": 2.0, "pfa": 0.01}
        with pytest.raises(ConfigError, match="'k' must be a positive integer"):
            config_from_dict(data)

    def test_k_exceeds_n_bands(self):
        data = {"n_bands": 8, "n_slots": 100, "k": 10, "detection_threshold": 2.0, "pfa": 0.01}
        with pytest.raises(ConfigError, match="cannot exceed 'n_bands'"):
            config_from_dict(data)

    @pytest.mark.parametrize("bad_pfa", [-0.1, 1.5, "high", True])
    def test_invalid_pfa(self, bad_pfa):
        data = {"n_bands": 8, "n_slots": 100, "k": 1, "detection_threshold": 2.0, "pfa": bad_pfa}
        with pytest.raises(ConfigError, match="'pfa' must be"):
            config_from_dict(data)

    def test_invalid_detection_threshold(self):
        data = {"n_bands": 8, "n_slots": 100, "k": 1, "detection_threshold": "high", "pfa": 0.01}
        with pytest.raises(ConfigError, match="'detection_threshold' must be a number"):
            config_from_dict(data)

    def test_invalid_seed(self):
        data = {"n_bands": 8, "n_slots": 100, "k": 1, "detection_threshold": 2.0, "pfa": 0.01, "seed": "zero"}
        with pytest.raises(ConfigError, match="'seed' must be an integer"):
            config_from_dict(data)

    def test_invalid_emitters_container(self):
        data = {"n_bands": 8, "n_slots": 100, "k": 1, "detection_threshold": 2.0, "pfa": 0.01, "emitters": "not_a_list"}
        with pytest.raises(ConfigError, match="'emitters' must be a list"):
            config_from_dict(data)

    def test_emitter_not_dict(self):
        data = {"n_bands": 8, "n_slots": 100, "k": 1, "detection_threshold": 2.0, "pfa": 0.01, "emitters": ["emitter_string"]}
        with pytest.raises(ConfigError, match="Emitter at index 0 must be a dictionary"):
            config_from_dict(data)

    def test_emitter_missing_fields(self):
        data = {
            "n_bands": 8,
            "n_slots": 100,
            "k": 1,
            "detection_threshold": 2.0,
            "pfa": 0.01,
            "emitters": [{"band": 0, "snr": 10.0}],
        }
        with pytest.raises(ConfigError, match="missing fields"):
            config_from_dict(data)

    @pytest.mark.parametrize("bad_band", [-1, 8, 10, "band0", True])
    def test_emitter_invalid_band(self, bad_band):
        data = {
            "n_bands": 8,
            "n_slots": 100,
            "k": 1,
            "detection_threshold": 2.0,
            "pfa": 0.01,
            "emitters": [
                {"band": bad_band, "snr": 10.0, "threat_level": 0.5, "emitter_type": "cw"}
            ],
        }
        with pytest.raises(ConfigError, match="must be an integer in range"):
            config_from_dict(data)

    def test_emitter_invalid_snr(self):
        data = {
            "n_bands": 8,
            "n_slots": 100,
            "k": 1,
            "detection_threshold": 2.0,
            "pfa": 0.01,
            "emitters": [
                {"band": 0, "snr": "invalid_snr", "threat_level": 0.5, "emitter_type": "cw"}
            ],
        }
        with pytest.raises(ConfigError, match="'snr' must be a number"):
            config_from_dict(data)

    def test_file_read_error(self, monkeypatch):
        path = Path("fake_path.yaml")
        monkeypatch.setattr(Path, "is_file", lambda self: True)
        def mock_read_text(self, encoding="utf-8"):
            raise OSError("Permission denied")
        monkeypatch.setattr(Path, "read_text", mock_read_text)
        with pytest.raises(ConfigError, match="Error reading config file"):
            load_config(path)

    def test_emitter_invalid_threat_level(self):
        data = {
            "n_bands": 8,
            "n_slots": 100,
            "k": 1,
            "detection_threshold": 2.0,
            "pfa": 0.01,
            "emitters": [
                {"band": 0, "snr": 10.0, "threat_level": -1.0, "emitter_type": "cw"}
            ],
        }
        with pytest.raises(ConfigError, match="'threat_level' must be a non-negative number"):
            config_from_dict(data)

    def test_emitter_invalid_type(self):
        data = {
            "n_bands": 8,
            "n_slots": 100,
            "k": 1,
            "detection_threshold": 2.0,
            "pfa": 0.01,
            "emitters": [
                {"band": 0, "snr": 10.0, "threat_level": 0.5, "emitter_type": "   "}
            ],
        }
        with pytest.raises(ConfigError, match="'emitter_type' must be a non-empty string"):
            config_from_dict(data)

    def test_emitter_invalid_params(self):
        data = {
            "n_bands": 8,
            "n_slots": 100,
            "k": 1,
            "detection_threshold": 2.0,
            "pfa": 0.01,
            "emitters": [
                {"band": 0, "snr": 10.0, "threat_level": 0.5, "emitter_type": "cw", "params": "invalid"}
            ],
        }
        with pytest.raises(ConfigError, match="'params' must be a dictionary"):
            config_from_dict(data)
