"""Scenario library for ewscan -- Experiment harness Task 3 (Phase 1E.8).

Provides three canned demo scenarios as specified in PLAN.md:
1. `sparse_bursty`: Sparse spectrum with 3 bursty Gilbert-Elliott Markov emitters
   and 13 empty bands. Demonstrates rapid arm identification.
2. `mixed_threat`: Mixed spectrum with a loud low-threat emitter, moderate emitters,
   and a rare high-threat emitter. Demonstrates threat discrimination and anti-camping.
3. `periodic_radar`: Structured pulsed radars with distinct periods, dwells, phases,
   and jitter. Demonstrates periodic signal capture and sets up Phase 2 Periodicity Sniper.

Each scenario separates adaptive learning schedulers (UCB1, Thompson Sampling)
from open-loop round-robin by a visible margin.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ewscan.contracts import EmitterInfo, EpisodeConfig


@dataclass(frozen=True)
class ScenarioMetadata:
    """Metadata and descriptive documentation for a canned demo scenario."""

    name: str
    title: str
    description: str
    tactical_rationale: str
    active_bands: tuple[int, ...]
    emitter_types: tuple[str, ...]


def make_sparse_bursty_scenario(
    n_bands: int = 16,
    n_slots: int = 2000,
    k: int = 1,
    detection_threshold: float | None = None,
    pfa: float = 1e-4,
    seed: int = 42,
) -> EpisodeConfig:
    """Create the 'sparse_bursty' canned demo scenario.

    Configuration:
    - 16 frequency bands, 2000 slots per episode.
    - Band 3: Gilbert-Elliott Markov emitter (p01=0.05, p10=0.20, duty ~20%, SNR=15 dB, threat=0.8).
    - Band 7: Gilbert-Elliott Markov emitter (p01=0.08, p10=0.24, duty ~25%, SNR=18 dB, threat=0.9).
    - Band 12: Gilbert-Elliott Markov emitter (p01=0.04, p10=0.16, duty ~20%, SNR=14 dB, threat=0.7).
    - 13 unassigned / empty bands.

    Tactical Rationale:
    Open-loop round-robin spends >80% of scan slots on empty spectrum. Adaptive learners
    quickly discover active bands and concentrate attention, achieving a 5-6x interception
    ratio advantage over round-robin.
    """
    emitters = (
        EmitterInfo(
            band=3,
            snr=15.0,
            threat_level=0.8,
            emitter_type="gilbert_elliott",
            params={"p01": 0.05, "p10": 0.20},
        ),
        EmitterInfo(
            band=7,
            snr=18.0,
            threat_level=0.9,
            emitter_type="gilbert_elliott",
            params={"p01": 0.08, "p10": 0.24},
        ),
        EmitterInfo(
            band=12,
            snr=14.0,
            threat_level=0.7,
            emitter_type="gilbert_elliott",
            params={"p01": 0.04, "p10": 0.16},
        ),
    )
    return EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=k,
        emitters=emitters,
        detection_threshold=detection_threshold,
        pfa=pfa,
        seed=seed,
    )


def make_mixed_threat_scenario(
    n_bands: int = 16,
    n_slots: int = 2000,
    k: int = 1,
    detection_threshold: float | None = None,
    pfa: float = 1e-4,
    seed: int = 42,
) -> EpisodeConfig:
    """Create the 'mixed_threat' canned demo scenario.

    Configuration:
    - 16 frequency bands, 2000 slots per episode.
    - Band 1: Loud Continuous Wave (CW) emitter (duty=100%, SNR=25 dB, threat=0.2).
    - Band 4: Periodic pulsed radar (period=40, dwell=8, jitter=1, phase=0, SNR=20 dB, threat=0.8).
    - Band 9: Gilbert-Elliott Markov emitter (p01=0.10, p10=0.10, duty ~50%, SNR=18 dB, threat=0.9).
    - Band 14: Critical rare threat Markov emitter (p01=0.03, p10=0.20, duty ~13%, SNR=22 dB, threat=1.0).
    - 12 unassigned / empty bands.

    Tactical Rationale:
    A naive greedy detector or open-loop scheduler gets trapped camping on Band 1
    (continuous loud signal) or ignores the rare critical threat on Band 14.
    A threat-aware adaptive scheduler balances high-threat intercept rate with
    staleness bonuses to discover and track all threats.
    """
    emitters = (
        EmitterInfo(
            band=1,
            snr=25.0,
            threat_level=0.2,
            emitter_type="cw",
            params={},
        ),
        EmitterInfo(
            band=4,
            snr=20.0,
            threat_level=0.8,
            emitter_type="periodic",
            params={"period": 40, "dwell": 8, "jitter": 1, "phase": 0},
        ),
        EmitterInfo(
            band=9,
            snr=18.0,
            threat_level=0.9,
            emitter_type="gilbert_elliott",
            params={"p01": 0.10, "p10": 0.10},
        ),
        EmitterInfo(
            band=14,
            snr=22.0,
            threat_level=1.0,
            emitter_type="gilbert_elliott",
            params={"p01": 0.03, "p10": 0.20},
        ),
    )
    return EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=k,
        emitters=emitters,
        detection_threshold=detection_threshold,
        pfa=pfa,
        seed=seed,
    )


def make_periodic_radar_scenario(
    n_bands: int = 16,
    n_slots: int = 2000,
    k: int = 1,
    detection_threshold: float | None = None,
    pfa: float = 1e-4,
    seed: int = 42,
) -> EpisodeConfig:
    """Create the 'periodic_radar' canned demo scenario.

    Configuration:
    - 16 frequency bands, 2000 slots per episode.
    - Band 2: Fast-scanning search radar (period=20, dwell=3, jitter=1, phase=5, SNR=20 dB, threat=0.9).
    - Band 8: Long-range tracking radar (period=50, dwell=5, jitter=2, phase=12, SNR=18 dB, threat=1.0).
    - Band 13: Surveillance radar (period=35, dwell=4, jitter=1, phase=0, SNR=15 dB, threat=0.7).
    - 13 unassigned / empty bands.

    Tactical Rationale:
    Evaluates intercept capabilities against multiple periodic scanning radars with
    different pulse repetition intervals, dwells, and jitter. Sets up the Phase 2
    periodicity sniper benchmark.
    """
    emitters = (
        EmitterInfo(
            band=2,
            snr=20.0,
            threat_level=0.9,
            emitter_type="periodic",
            params={"period": 20, "dwell": 3, "jitter": 1, "phase": 5},
        ),
        EmitterInfo(
            band=8,
            snr=18.0,
            threat_level=1.0,
            emitter_type="periodic",
            params={"period": 50, "dwell": 5, "jitter": 2, "phase": 12},
        ),
        EmitterInfo(
            band=13,
            snr=15.0,
            threat_level=0.7,
            emitter_type="periodic",
            params={"period": 35, "dwell": 4, "jitter": 1, "phase": 0},
        ),
    )
    return EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=k,
        emitters=emitters,
        detection_threshold=detection_threshold,
        pfa=pfa,
        seed=seed,
    )


# Registry of canned scenario builder functions
SCENARIO_BUILDERS: dict[str, Callable[..., EpisodeConfig]] = {
    "sparse_bursty": make_sparse_bursty_scenario,
    "mixed_threat": make_mixed_threat_scenario,
    "periodic_radar": make_periodic_radar_scenario,
}

# Alias resolution mapping
SCENARIO_ALIASES: dict[str, str] = {
    "sparse": "sparse_bursty",
    "sparse_and_bursty": "sparse_bursty",
    "bursty": "sparse_bursty",
    "mixed": "mixed_threat",
    "mixed_high_threat": "mixed_threat",
    "mixed_threats": "mixed_threat",
    "threat": "mixed_threat",
    "radar": "periodic_radar",
    "periodic": "periodic_radar",
    "periodic_radars": "periodic_radar",
}

# Metadata descriptions for UI and reporting
SCENARIO_METADATA: dict[str, ScenarioMetadata] = {
    "sparse_bursty": ScenarioMetadata(
        name="sparse_bursty",
        title="Sparse and Bursty Spectrum",
        description="16 bands with 3 bursty Markov emitters and 13 quiet bands.",
        tactical_rationale="Tests arm identification speed in sparse spectrum environments.",
        active_bands=(3, 7, 12),
        emitter_types=("gilbert_elliott", "gilbert_elliott", "gilbert_elliott"),
    ),
    "mixed_threat": ScenarioMetadata(
        name="mixed_threat",
        title="Mixed Threat Spectrum",
        description="16 bands with CW background, periodic radar, Markov emitter, and a rare high threat.",
        tactical_rationale="Tests threat discrimination and anti-camping under loud background activity.",
        active_bands=(1, 4, 9, 14),
        emitter_types=("cw", "periodic", "gilbert_elliott", "gilbert_elliott"),
    ),
    "periodic_radar": ScenarioMetadata(
        name="periodic_radar",
        title="Periodic Radar Spectrum",
        description="16 bands with 3 periodic radars of differing periods, dwells, and phase offsets.",
        tactical_rationale="Tests periodic signal interception and tracking across multiple pulse rates.",
        active_bands=(2, 8, 13),
        emitter_types=("periodic", "periodic", "periodic"),
    ),
}


def canonical_scenario_name(name: str) -> str:
    """Normalize and resolve a scenario name or alias to its canonical string.

    Parameters
    ----------
    name : str
        User-provided scenario name string (case-insensitive, hyphens/underscores allowed).

    Returns
    -------
    str
        Canonical scenario name ('sparse_bursty', 'mixed_threat', 'periodic_radar').

    Raises
    ------
    ValueError
        If the scenario name cannot be resolved.
    """
    clean = name.strip().lower().replace("-", "_").replace(".yaml", "").replace(".yml", "")
    # Remove leading path components if a filename was provided
    if "/" in clean or "\\" in clean:
        import os

        clean = os.path.splitext(os.path.basename(clean))[0]

    if clean in SCENARIO_BUILDERS:
        return clean
    if clean in SCENARIO_ALIASES:
        return SCENARIO_ALIASES[clean]

    available = ", ".join(list_scenarios())
    raise ValueError(f"Unknown scenario '{name}'. Available scenarios: {available}")


def get_scenario(name: str, **kwargs: Any) -> EpisodeConfig:
    """Instantiate a canned demo scenario by name or alias.

    Parameters
    ----------
    name : str
        Scenario name identifier ('sparse_bursty', 'mixed_threat', 'periodic_radar', or alias).
    **kwargs : Any
        Optional overrides for scenario parameters (e.g. n_slots, seed, n_bands).

    Returns
    -------
    EpisodeConfig
        Fully configured scenario EpisodeConfig instance.
    """
    canonical = canonical_scenario_name(name)
    builder = SCENARIO_BUILDERS[canonical]
    return builder(**kwargs)


def list_scenarios() -> list[str]:
    """Return a list of all canonical scenario names in the scenario library.

    Returns
    -------
    list[str]
        List of scenario names: ['sparse_bursty', 'mixed_threat', 'periodic_radar'].
    """
    return list(SCENARIO_BUILDERS.keys())


def get_scenario_metadata(name: str) -> ScenarioMetadata:
    """Retrieve metadata description for a scenario.

    Parameters
    ----------
    name : str
        Scenario name or alias.

    Returns
    -------
    ScenarioMetadata
        Metadata dataclass for the scenario.
    """
    canonical = canonical_scenario_name(name)
    return SCENARIO_METADATA[canonical]


def get_all_scenarios(**kwargs: Any) -> dict[str, EpisodeConfig]:
    """Instantiate all canned demo scenarios into a dictionary.

    Parameters
    ----------
    **kwargs : Any
        Optional overrides applied to all scenarios (e.g. seed, n_slots).

    Returns
    -------
    dict[str, EpisodeConfig]
        Mapping of canonical scenario names to instantiated EpisodeConfig objects.
    """
    return {name: builder(**kwargs) for name, builder in SCENARIO_BUILDERS.items()}
