"""Unit tests for signal emitters -- 1B.1, 1B.2, 1B.3.

Verifies:
- GilbertElliottEmitter: Duty cycle over 100k slots matches p01 / (p01 + p10).
- PeriodicEmitter: ON slots land at expected indices; jitter stays in bounds.
- StaticCWEmitter: ON in every slot.
- Determinism and reset behavior across all emitters.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.contracts import EmitterInfo
from ewscan.env import (
    FrequencyHopEmitter,
    GilbertElliottEmitter,
    PeriodicEmitter,
    StaticCWEmitter,
)


# -----------------------------------------------------------------------
# 1B.1 GilbertElliottEmitter
# -----------------------------------------------------------------------

class TestGilbertElliottEmitter:
    def test_unreset_raises(self):
        e = GilbertElliottEmitter(band=0, p01=0.1, p10=0.2)
        with pytest.raises(RuntimeError, match="must be reset"):
            e.step()

    def test_parameter_validation(self):
        with pytest.raises(ValueError, match="p01"):
            GilbertElliottEmitter(band=0, p01=-0.1, p10=0.2)
        with pytest.raises(ValueError, match="p10"):
            GilbertElliottEmitter(band=0, p01=0.1, p10=1.5)
        with pytest.raises(ValueError, match="cannot both be 0"):
            GilbertElliottEmitter(band=0, p01=0.0, p10=0.0)
        with pytest.raises(ValueError, match="initial_state"):
            GilbertElliottEmitter(band=0, p01=0.1, p10=0.2, initial_state=2)

    def test_duty_cycle_matches_stationary(self):
        """PLAN.md 1B.1 verify check:
        Duty cycle over 100k slots matches p01/(p01+p10).
        """
        p01 = 0.2
        p10 = 0.3
        expected_p_on = p01 / (p01 + p10)  # 0.40

        e = GilbertElliottEmitter(band=0, p01=p01, p10=p10)
        rng = np.random.default_rng(42)
        e.reset(rng)

        n_slots = 100_000
        on_count = sum(e.step() for _ in range(n_slots))
        empirical_p_on = on_count / n_slots

        assert abs(empirical_p_on - expected_p_on) < 0.01, (
            f"Empirical duty cycle {empirical_p_on:.4f} differs from expected "
            f"{expected_p_on:.4f} by more than 1%"
        )

    def test_determinism(self):
        e = GilbertElliottEmitter(band=1, p01=0.15, p10=0.25)
        rng1 = np.random.default_rng(123)
        e.reset(rng1)
        seq1 = [e.step() for _ in range(200)]

        rng2 = np.random.default_rng(123)
        e.reset(rng2)
        seq2 = [e.step() for _ in range(200)]

        assert seq1 == seq2

    def test_explicit_initial_state(self):
        e_on = GilbertElliottEmitter(band=0, p01=0.1, p10=0.2, initial_state=1)
        rng = np.random.default_rng(0)
        e_on.reset(rng)
        assert e_on.step() is True

        e_off = GilbertElliottEmitter(band=0, p01=0.1, p10=0.2, initial_state=0)
        e_off.reset(rng)
        assert e_off.step() is False

    def test_info(self):
        e = GilbertElliottEmitter(
            band=2, p01=0.3, p10=0.1, snr=15.0, threat_level=0.8
        )
        info = e.info
        assert isinstance(info, EmitterInfo)
        assert info.band == 2
        assert info.snr == 15.0
        assert info.threat_level == 0.8
        assert info.emitter_type == "gilbert_elliott"
        assert info.params == {"p01": 0.3, "p10": 0.1}


# -----------------------------------------------------------------------
# 1B.2 PeriodicEmitter
# -----------------------------------------------------------------------

class TestPeriodicEmitter:
    def test_unreset_raises(self):
        e = PeriodicEmitter(band=0, period=5)
        with pytest.raises(RuntimeError, match="must be reset"):
            e.step()

    def test_parameter_validation(self):
        with pytest.raises(ValueError, match="period"):
            PeriodicEmitter(band=0, period=0)
        with pytest.raises(ValueError, match="dwell"):
            PeriodicEmitter(band=0, period=5, dwell=6)
        with pytest.raises(ValueError, match="jitter"):
            PeriodicEmitter(band=0, period=5, jitter=-1)
        with pytest.raises(ValueError, match="phase"):
            PeriodicEmitter(band=0, period=5, phase=-1)

    def test_zero_jitter_expected_indices(self):
        """PLAN.md 1B.2 verify check:
        ON slots land at expected indices for zero jitter.
        """
        # Period 5, dwell 2, phase 1 -> ON at slots 1,2, 6,7, 11,12...
        e = PeriodicEmitter(band=0, period=5, dwell=2, jitter=0, phase=1)
        rng = np.random.default_rng(0)
        e.reset(rng)

        seq = [e.step() for _ in range(20)]
        expected = [
            False, True, True, False, False,  # slots 0..4 (ON at 1,2)
            False, True, True, False, False,  # slots 5..9 (ON at 6,7)
            False, True, True, False, False,  # slots 10..14 (ON at 11,12)
            False, True, True, False, False,  # slots 15..19 (ON at 16,17)
        ]
        assert seq == expected

    def test_jitter_stays_in_bounds(self):
        """PLAN.md 1B.2 verify check:
        Jitter stays in bounds [-J, J].
        """
        period = 10
        dwell = 1
        jitter = 2
        phase = 0
        e = PeriodicEmitter(
            band=0, period=period, dwell=dwell, jitter=jitter, phase=phase
        )

        rng = np.random.default_rng(99)
        e.reset(rng)

        n_slots = 500
        seq = [e.step() for _ in range(n_slots)]

        # Group ON slots by period index and check start offset
        on_slots = [t for t, is_on in enumerate(seq) if is_on]
        assert len(on_slots) > 0

        for t in on_slots:
            k = round((t - phase) / period)
            expected_base = k * period + phase
            offset = t - expected_base
            assert -jitter <= offset <= jitter, (
                f"Slot {t} for period {k} has offset {offset}, outside [-{jitter}, {jitter}]"
            )

    def test_determinism(self):
        e = PeriodicEmitter(band=2, period=7, dwell=2, jitter=1, phase=3)
        rng1 = np.random.default_rng(42)
        e.reset(rng1)
        seq1 = [e.step() for _ in range(100)]

        rng2 = np.random.default_rng(42)
        e.reset(rng2)
        seq2 = [e.step() for _ in range(100)]

        assert seq1 == seq2

    def test_info(self):
        e = PeriodicEmitter(
            band=3, period=12, dwell=3, jitter=1, phase=2, snr=18.0, threat_level=0.5
        )
        info = e.info
        assert isinstance(info, EmitterInfo)
        assert info.band == 3
        assert info.snr == 18.0
        assert info.threat_level == 0.5
        assert info.emitter_type == "periodic"
        assert info.params == {"period": 12, "dwell": 3, "jitter": 1, "phase": 2}


# -----------------------------------------------------------------------
# 1B.3 StaticCWEmitter
# -----------------------------------------------------------------------

class TestStaticCWEmitter:
    def test_unreset_raises(self):
        e = StaticCWEmitter(band=0)
        with pytest.raises(RuntimeError, match="must be reset"):
            e.step()

    def test_always_on(self):
        """PLAN.md 1B.3 verify check:
        ON in every slot.
        """
        e = StaticCWEmitter(band=0, snr=20.0, threat_level=1.0)
        rng = np.random.default_rng(0)
        e.reset(rng)

        for _ in range(10_000):
            assert e.step() is True

    def test_info(self):
        e = StaticCWEmitter(band=4, snr=25.0, threat_level=0.9)
        info = e.info
        assert isinstance(info, EmitterInfo)
        assert info.band == 4
        assert info.snr == 25.0
        assert info.threat_level == 0.9
        assert info.emitter_type == "cw"
        assert info.params == {}


# -----------------------------------------------------------------------
# Sprint 2 FrequencyHopEmitter
# -----------------------------------------------------------------------

class TestFrequencyHopEmitter:
    def test_unreset_raises(self):
        e = FrequencyHopEmitter(band=0, hop_bands=[0, 1, 2, 3])
        with pytest.raises(RuntimeError, match="must be reset"):
            e.step()

    def test_validation(self):
        with pytest.raises(ValueError, match="hop_bands"):
            FrequencyHopEmitter(band=0, hop_bands=[])
        with pytest.raises(ValueError, match="hop_bands"):
            FrequencyHopEmitter(band=0, hop_bands=[0, -1])
        with pytest.raises(ValueError, match="sequence"):
            FrequencyHopEmitter(band=0, hop_bands=[0, 1], sequence="nope")
        with pytest.raises(ValueError, match="state"):
            FrequencyHopEmitter(band=0, hop_bands=[0, 1], state=0)

    def test_always_on(self):
        e = FrequencyHopEmitter(band=0, hop_bands=[0, 1, 2, 3])
        e.reset(np.random.default_rng(0))
        for _ in range(1000):
            assert e.step() is True

    def test_lfsr_known_band_sequence(self):
        """Known LFSR taps produce a known band sequence.

        4-bit Fibonacci LFSR, taps=[3,2], initial state=1. Band picked from the
        current state (state % len(hop_bands)) before advancing. Hand-derived
        states: [1,2,4,9,3,6,13,10]; % 4 gives bands [1,2,0,1,3,2,1,2].
        """
        e = FrequencyHopEmitter(
            band=0,
            hop_bands=[0, 1, 2, 3],
            sequence="lfsr",
            taps=[3, 2],
            state=1,
            n_bits=4,
        )
        e.reset(np.random.default_rng(0))

        expected = [1, 2, 0, 1, 3, 2, 1, 2]
        got = []
        for _ in range(len(expected)):
            e.step()
            got.append(e.current_band)
        assert got == expected

    def test_current_band_reflects_last_step(self):
        e = FrequencyHopEmitter(band=0, hop_bands=[5, 6], sequence="lfsr",
                                taps=[3, 2], state=1, n_bits=4)
        e.reset(np.random.default_rng(0))
        e.step()
        assert e.current_band in (5, 6)

    def test_logistic_deterministic(self):
        kw = dict(band=0, hop_bands=[0, 1, 2, 3], sequence="logistic",
                  r=3.9, x0=0.5)
        a = FrequencyHopEmitter(**kw)
        b = FrequencyHopEmitter(**kw)
        a.reset(np.random.default_rng(0))
        b.reset(np.random.default_rng(999))
        seq_a = [(a.step(), a.current_band) for _ in range(200)]
        seq_b = [(b.step(), b.current_band) for _ in range(200)]
        assert seq_a == seq_b
        assert all(band in (0, 1, 2, 3) for _, band in seq_a)

    def test_reset_determinism(self):
        e = FrequencyHopEmitter(band=0, hop_bands=[0, 1, 2, 3], sequence="lfsr",
                                taps=[3, 2], state=1, n_bits=4)
        e.reset(np.random.default_rng(0))
        first = [(e.step(), e.current_band) for _ in range(50)]
        e.reset(np.random.default_rng(0))
        second = [(e.step(), e.current_band) for _ in range(50)]
        assert first == second

    def test_info_roundtrip(self):
        e = FrequencyHopEmitter(band=2, hop_bands=[2, 5, 8], snr=15.0,
                                threat_level=0.7, sequence="lfsr",
                                taps=[3, 2], state=1, n_bits=4)
        info = e.info
        assert info.band == 2
        assert info.snr == 15.0
        assert info.emitter_type == "frequency_hop"
        assert info.params["hop_bands"] == [2, 5, 8]
        assert info.params["sequence"] == "lfsr"
