"""Phase-conditioned occupancy posterior for sparsely scanned bands.

At k=1 across 16 bands a band is revisited every 11-16 slots. A Markov belief
propagated over that gap decays to its stationary prior, so it carries no
information at selection time. Indexing occupancy by ``slot % period`` instead
of by elapsed time removes the decay entirely: the estimate is as sharp after a
100-slot gap as after one slot.

A wrong period needs no rejection gate. It spreads hits evenly over its phase
buckets, so the phase posterior collapses onto the band's marginal rate and the
model contributes nothing. Only a period that concentrates hits changes any
decision.

Reads (band, slot, detection) only. Never emitter truth or emitter parameters.
"""

from __future__ import annotations

import math

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.history import HitHistory
from ewscan.agents.period import (
    _aperiodic_likelihood,
    _phase_likelihood,
    estimate_period_model_candidates,
)


# Evidence a long-period candidate must show over the aperiodic model before
# it displaces the gap-divisor fit. Matches the short-period fitter's bar.
_MIN_LONG_PERIOD_MARGIN = 3.5
_COUPLED_PERIOD_FLOOR = 201
_MIN_COUPLED_MARGIN = 10.0


class PhaseOccupancy:
    """Per-band posterior over P(band is ON at slot t), indexed by slot phase.

    Parameters
    ----------
    n_bands : int
        Number of frequency bands.
    capacity : int
        Ring-buffer capacity for each band's observation history.
    refit_interval : int, default 48
        Observations on a band between period refits. Refitting on a cadence
        rather than on every detection is what keeps the runtime bounded.
    min_hits : int, default 6
        Hits required on a band before a period fit is attempted.
    smoothing : int, default 1
        Circular half-width pooled around the queried phase. Absorbs emitter
        jitter and lends support to phase buckets with few observations.
    prior_strength : float, default 4.0
        Pseudo-count shrinking each phase bucket toward the band's marginal
        rate. This is what makes a wrong period harmless.
    max_period : int, default 200
        Longest period the fitter will consider.
    pd : float, default 0.9
        Nominal detection probability, used to weigh the last observation in
        the recency term.
    pfa : float, default 0.01
        False-alarm probability, used for the same purpose.
    survey_weight : float, default 0.3
        Optimism added to a band that has never produced a hit. Securing a
        first intercept on every emitter is a separate objective from maximum
        occupancy; without this the scheduler correctly, and uselessly, prefers
        the incumbent for ever.
    survey_duty : float, default 0.03
        Lowest emitter duty cycle the survey term insists on ruling out.
    """

    def __init__(
        self,
        n_bands: int,
        capacity: int,
        refit_interval: int = 48,
        min_hits: int = 6,
        smoothing: int = 1,
        prior_strength: float = 4.0,
        max_period: int = 200,
        pd: float = 0.9,
        pfa: float = 0.01,
        survey_weight: float = 0.3,
        survey_duty: float = 0.03,
    ) -> None:
        self._n_bands = int(n_bands)
        self._history = HitHistory(n_bands, capacity)
        self._refit_interval = int(refit_interval)
        self._min_hits = int(min_hits)
        self._smoothing = int(smoothing)
        self._prior_strength = float(prior_strength)
        self._max_period = int(max_period)
        self._coupled_max_period = max(280, self._max_period)
        self._pd = float(pd)
        self._pfa = float(pfa)
        self._survey_weight = float(survey_weight)
        self._survey_duty = float(survey_duty)

        self._counts = np.zeros(n_bands, dtype=np.int64)
        self._hits = np.zeros(n_bands, dtype=np.int64)
        self._since_refit = np.zeros(n_bands, dtype=np.int64)
        self._period: list[int | None] = [None] * n_bands
        self._obs_phase: list[NDArray[np.float64] | None] = [None] * n_bands
        self._hit_phase: list[NDArray[np.float64] | None] = [None] * n_bands
        self._long_candidates: list[tuple[int, ...]] = [()] * n_bands
        self._coupled_period: int | None = None
        self._coupled_members: tuple[int, ...] = ()
        self._coupled_member_index: dict[int, int] = {}
        self._coupled_log_likelihood: NDArray[np.float64] | None = None
        self._coupled_evidence: NDArray[np.int64] | None = None
        self._coupled_survey_counts: NDArray[np.int64] | None = None

        # Adjacent-slot transition counts, for the recency term. The prior is
        # deliberately sticky (p01 = p10 = 0.1): a band assumed to hold its
        # state is a band worth revisiting straight after a hit, which is the
        # only way an adjacent pair ever forms at k=1.
        self._n00 = np.full(n_bands, 9.0, dtype=np.float64)
        self._n01 = np.full(n_bands, 1.0, dtype=np.float64)
        self._n11 = np.full(n_bands, 9.0, dtype=np.float64)
        self._n10 = np.full(n_bands, 1.0, dtype=np.float64)
        self._last_slot = np.full(n_bands, -1, dtype=np.int64)
        self._last_det = np.zeros(n_bands, dtype=bool)

    def observe(self, band: int, slot: int, detection: bool) -> None:
        """Fold one scan outcome into the marginal and phase statistics."""
        self._history.append(band, slot, detection)
        self._counts[band] += 1
        if detection:
            self._hits[band] += 1

        if slot - self._last_slot[band] == 1:
            previous = bool(self._last_det[band])
            if previous:
                target = self._n11 if detection else self._n10
            else:
                target = self._n01 if detection else self._n00
            target[band] += 1.0
        self._last_slot[band] = slot
        self._last_det[band] = detection

        period = self._period[band]
        if period is not None:
            phase = slot % period
            obs_phase = self._obs_phase[band]
            hit_phase = self._hit_phase[band]
            assert obs_phase is not None and hit_phase is not None
            obs_phase[phase] += 1.0
            if detection:
                hit_phase[phase] += 1.0

        self._since_refit[band] += 1
        # A band short of min_hits must not burn its refit slot, or the first
        # fit lands a whole interval after the evidence for it arrived. The
        # interval then grows with the evidence already in hand: refitting is
        # the dominant episode cost and a settled estimate rarely moves.
        due = max(self._refit_interval, int(self._counts[band]) // 4)
        rebuilt_coupled = False
        if self._since_refit[band] >= due and int(self._hits[band]) >= self._min_hits:
            self._refit(band)
            rebuilt_coupled = self._refresh_coupled_group()
        if not rebuilt_coupled:
            self._update_coupled(band, slot, detection)

    def _phase_hit_support(self, band: int, period: int) -> set[int]:
        slots, detections = self._history.recent(band)
        return set((slots[detections] % period).tolist())

    def _compatible_group_members(self, seed: int, period: int) -> tuple[int, ...]:
        supports = [self._phase_hit_support(band, period) for band in range(self._n_bands)]
        members = [seed]
        candidates = sorted(
            (band for band in range(self._n_bands) if band != seed),
            key=lambda band: int(self._hits[band]),
            reverse=True,
        )
        for band in candidates:
            count = int(self._counts[band])
            hits = int(self._hits[band])
            if count < 8 or hits == 0:
                continue
            rate = hits / count
            if not 0.05 <= rate <= 0.6:
                continue
            fitted = self._period[band]
            if fitted is not None and period % fitted != 0 and fitted % period != 0:
                continue
            if any(supports[band] & supports[member] for member in members):
                continue
            members.append(band)

        total_rate = sum(
            int(self._hits[band]) / int(self._counts[band]) for band in members
        )
        if len(members) < 3 or total_rate < 0.45 or total_rate > 1.35:
            return ()
        return tuple(sorted(members))

    def _refresh_coupled_group(self) -> bool:
        proposals = {
            (band, period)
            for band, periods in enumerate(self._long_candidates)
            for period in periods
        }
        proposals.update(
            (band, period)
            for band, period in enumerate(self._period)
            if period is not None and period >= _COUPLED_PERIOD_FLOOR
        )
        if not proposals:
            return False

        choices = []
        for seed, period in proposals:
            members = self._compatible_group_members(seed, period)
            if members:
                choices.append((self._coupled_margin(members, period), period, members))
        if not choices:
            return False
        margin, period, members = max(choices)
        if margin < _MIN_COUPLED_MARGIN:
            return False
        if period == self._coupled_period and members == self._coupled_members:
            return False

        first_group = self._coupled_period is None
        self._coupled_period = period
        self._coupled_members = members
        self._coupled_member_index = {
            member: index for index, member in enumerate(members)
        }
        self._coupled_log_likelihood = np.zeros(
            (period, len(members)), dtype=np.float64
        )
        self._coupled_evidence = np.zeros(period, dtype=np.int64)
        if first_group:
            self._coupled_survey_counts = self._counts.copy()
        observations: list[tuple[int, int, bool]] = []
        for member in members:
            slots, detections = self._history.recent(member)
            observations.extend(
                (int(slot), member, bool(detection))
                for slot, detection in zip(slots, detections)
            )
        for slot, member, detection in observations:
            self._update_coupled(member, slot, detection)
        return True

    def _coupled_margin(self, members: tuple[int, ...], period: int) -> float:
        member_count = len(members)
        observations = np.zeros(period, dtype=np.float64)
        hits = np.zeros(period, dtype=np.float64)
        selected_observations = []
        selected_hits = []
        null_score = 0.0
        for member in members:
            slots, detections = self._history.recent(member)
            phases = slots % period
            member_observations = np.bincount(phases, minlength=period).astype(
                np.float64
            )
            member_hits = np.bincount(
                phases[detections], minlength=period
            ).astype(np.float64)
            selected_observations.append(member_observations)
            selected_hits.append(member_hits)
            observations += member_observations
            hits += member_hits

            rate = (float(detections.sum()) + 0.5) / (len(detections) + 1.0)
            null_score += float(detections.sum()) * math.log(rate)
            null_score += (len(detections) - float(detections.sum())) * math.log(
                1.0 - rate
            )

        base = hits * math.log(max(self._pfa, 1e-12))
        base += (observations - hits) * math.log(max(1.0 - self._pfa, 1e-12))
        log_likelihood = np.repeat(base[:, None], member_count, axis=1)
        hit_delta = math.log(max(self._pd, 1e-12)) - math.log(
            max(self._pfa, 1e-12)
        )
        miss_delta = math.log(max(1.0 - self._pd, 1e-12)) - math.log(
            max(1.0 - self._pfa, 1e-12)
        )
        for index in range(member_count):
            member_hits = selected_hits[index]
            member_misses = selected_observations[index] - member_hits
            log_likelihood[:, index] += (
                member_hits * hit_delta + member_misses * miss_delta
            )

        populated = observations > 0.0
        rows = log_likelihood[populated]
        maxima = rows.max(axis=1)
        group_score = float(
            np.sum(
                maxima
                + np.log(np.exp(rows - maxima[:, None]).sum(axis=1))
                - math.log(member_count)
            )
        )
        return group_score - null_score

    def _update_coupled(self, band: int, slot: int, detection: bool) -> None:
        if (
            self._coupled_period is None
            or band not in self._coupled_member_index
            or self._coupled_log_likelihood is None
            or self._coupled_evidence is None
        ):
            return
        phase = slot % self._coupled_period
        index = self._coupled_member_index[band]
        if detection:
            other = math.log(max(self._pfa, 1e-12))
            selected = math.log(max(self._pd, 1e-12))
        else:
            other = math.log(max(1.0 - self._pfa, 1e-12))
            selected = math.log(max(1.0 - self._pd, 1e-12))
        self._coupled_log_likelihood[phase] += other
        self._coupled_log_likelihood[phase, index] += selected - other
        self._coupled_evidence[phase] += 1

    def _coupled_posterior(self, band: int, slot: int) -> tuple[float, float] | None:
        if (
            self._coupled_period is None
            or band not in self._coupled_member_index
            or self._coupled_log_likelihood is None
            or self._coupled_evidence is None
        ):
            return None
        phase = slot % self._coupled_period
        logits = self._coupled_log_likelihood[phase]
        weights = np.exp(logits - float(logits.max()))
        holder_probability = float(
            weights[self._coupled_member_index[band]] / weights.sum()
        )
        mean = holder_probability * self._pd + (1.0 - holder_probability) * self._pfa
        evidence = int(self._coupled_evidence[phase])
        spread = math.sqrt(mean * (1.0 - mean) / (evidence + 1.0))
        return mean, spread

    def _autocorr_candidates(
        self,
        slots: NDArray[np.intp],
        detections: NDArray[np.bool_],
        top: int = 4,
    ) -> tuple[int, ...]:
        """Long-period candidates from the observed series' autocorrelation.

        The gap-divisor generator only compares hits lying within a short
        window of each other, so a period longer than that window is never
        proposed at all: on a 255-slot frequency-hop cycle it never considers
        the answer. One FFT proposes it directly. Harmonics it also proposes
        are filtered by the likelihood, which charges for the extra phase
        buckets, so each peak is offered alongside its half.
        """
        first = int(slots[0])
        span = int(slots[-1]) - first + 1
        highest = min(self._coupled_max_period, span // 3)
        if span < 12 or highest < 2:
            return ()

        series = np.zeros(span, dtype=np.float64)
        series[np.asarray(slots, dtype=np.intp)[detections] - first] = 1.0
        series -= series.mean()
        size = 1 << int(np.ceil(np.log2(2 * span)))
        spectrum = np.fft.rfft(series, size)
        correlation = np.fft.irfft(spectrum * np.conj(spectrum), size)[:span]

        peaks = np.argsort(correlation[2 : highest + 1])[::-1][:top] + 2
        candidates: set[int] = set()
        for peak in peaks.tolist():
            candidates.add(int(peak))
            if peak % 2 == 0 and peak // 2 >= 2:
                candidates.add(int(peak // 2))
        return tuple(sorted(candidates))

    def _refit(self, band: int) -> None:
        """Re-estimate the band's period and rebuild its phase histogram."""
        self._since_refit[band] = 0
        slots, detections = self._history.recent(band)
        model = estimate_period_model_candidates(
            slots,
            detections,
            min_hits=self._min_hits,
            holdout_fraction=0.0,
            max_period=self._max_period,
        )
        period = None if model is None else int(model.period)

        # Offered even when the gap generator did return a period: on a long
        # cycle it reliably returns a short divisor of the true one, which is
        # worse than returning nothing. The likelihood arbitrates.
        all_candidates = self._autocorr_candidates(slots, detections)
        self._long_candidates[band] = tuple(
            candidate
            for candidate in all_candidates
            if candidate >= _COUPLED_PERIOD_FLOOR
        )
        candidates = tuple(
            candidate
            for candidate in all_candidates
            if candidate <= self._max_period
        )
        if candidates:
            null = _aperiodic_likelihood(slots, detections)
            best = max(
                candidates, key=lambda p: _phase_likelihood(slots, detections, p)
            )
            best_margin = _phase_likelihood(slots, detections, best) - null
            standing = (
                float("-inf")
                if period is None
                else _phase_likelihood(slots, detections, period) - null
            )
            if best_margin > max(standing, _MIN_LONG_PERIOD_MARGIN):
                period = best

        if period is None:
            self._period[band] = None
            self._obs_phase[band] = None
            self._hit_phase[band] = None
            return

        phases = np.asarray(slots, dtype=np.int64) % period
        self._period[band] = period
        self._obs_phase[band] = np.bincount(
            phases, minlength=period
        ).astype(np.float64)
        self._hit_phase[band] = np.bincount(
            phases[np.asarray(detections, dtype=bool)], minlength=period
        ).astype(np.float64)

    def _marginal(self, band: int) -> float:
        """Jeffreys posterior mean of the band's unconditional ON rate."""
        return float(
            (self._hits[band] + 0.5) / (self._counts[band] + 1.0)
        )

    def _phase_evidence(self, band: int, slot: int) -> tuple[float, float]:
        """Return (hits, observations) for this slot's phase.

        The exact bucket is used whenever it holds any observation. Emitter
        jitter is part of the phase distribution, so pooling neighbours would
        blur a real signal; it is only a fallback for a phase never scanned.
        """
        period = self._period[band]
        if period is None:
            return float(self._hits[band]), float(self._counts[band])

        obs_phase = self._obs_phase[band]
        hit_phase = self._hit_phase[band]
        assert obs_phase is not None and hit_phase is not None
        phase = slot % period
        if obs_phase[phase] > 0.0:
            return float(hit_phase[phase]), float(obs_phase[phase])

        width = min(self._smoothing, (period - 1) // 2)
        if width <= 0:
            return 0.0, 0.0

        window = (np.arange(-width, width + 1) + phase) % period
        return float(hit_phase[window].sum()), float(obs_phase[window].sum())

    def _recency_weight(self, band: int, slot: int) -> float:
        """Fraction of the last observation still valid after the revisit gap.

        ``lambda^gap`` for the band's own two-state chain. This is the half of
        the belief state that survives at k=1: the band scanned last slot is
        still informative, every other band has decayed to its prior.
        """
        gap = int(slot) - int(self._last_slot[band])
        if self._last_slot[band] < 0 or gap < 1:
            return 0.0
        p01 = self._n01[band] / (self._n00[band] + self._n01[band])
        p10 = self._n10[band] / (self._n11[band] + self._n10[band])
        decay = 1.0 - p01 - p10
        if decay <= 0.0:
            return 0.0
        return float(decay**gap)

    def posterior(self, band: int, slot: int) -> tuple[float, float]:
        """Return (mean, standard deviation) of P(ON) for this band and slot.

        The prior pseudo-counts stabilise the mean but deliberately do not
        count toward the spread. A (band, phase) cell nobody has observed must
        stay maximally uncertain, or the scheduler stops exploring it.
        """
        coupled = self._coupled_posterior(band, slot)
        if coupled is not None:
            return coupled

        marginal = self._marginal(band)
        hits, observations = self._phase_evidence(band, slot)
        kappa = self._prior_strength
        mean = (hits + kappa * marginal) / (observations + kappa)
        spread = math.sqrt(mean * (1.0 - mean) / (observations + 1.0))

        # A fitted period already describes the emitter's timing completely, so
        # the recency term would only fight it. It applies where there is no
        # periodic structure to index, which is exactly where it is needed.
        if self._period[band] is not None:
            return mean, spread

        weight = self._recency_weight(band, slot)
        if weight <= 0.0:
            return mean, spread

        # A miss is not proof the band went silent. Fold the last observation
        # in through the detector model, or one missed detection on an
        # always-on band throws the scheduler off it.
        span = self._pd - self._pfa
        prior_on = (
            min(1.0, max(0.0, (mean - self._pfa) / span)) if span > 1e-12 else mean
        )
        detected = bool(self._last_det[band])
        l_on = self._pd if detected else 1.0 - self._pd
        l_off = self._pfa if detected else 1.0 - self._pfa
        denom = l_on * prior_on + l_off * (1.0 - prior_on)
        posterior_on = (l_on * prior_on / denom) if denom > 1e-12 else prior_on
        on_now = prior_on + (posterior_on - prior_on) * weight
        return on_now * self._pd + (1.0 - on_now) * self._pfa, spread

    def occupancy(self, slot: int) -> NDArray[np.float64]:
        """Posterior mean P(ON at ``slot``) for every band."""
        return np.array(
            [self.posterior(band, slot)[0] for band in range(self._n_bands)],
            dtype=np.float64,
        )

    @staticmethod
    def _wilson_half_width(hits: float, observations: float, z: float) -> float:
        """Wilson score half-width for (hits, observations).

        The plug-in spread ``sqrt(p(1-p)/n)`` collapses as p approaches zero,
        so a handful of misses makes a low-duty emitter look exactly like a
        dead band and it is never scanned again. Zero hits in ten looks is a
        35% event for a 10%-duty emitter; the Wilson width keeps saying so.
        """
        if observations <= 0.0:
            return 1.0
        denominator = observations + z * z
        return (z / denominator) * math.sqrt(
            hits * (observations - hits) / observations + 0.25 * z * z
        )

    def _survey_bonus(self, band: int) -> float:
        """Optimism for a band that has never once been caught transmitting.

        ``(1 - duty)^n`` is the chance a ``survey_duty`` emitter would have been
        missed by every look so far, so the term vanishes by itself once the
        band has been looked at often enough to rule one out. It is bounded and
        it self-disables: where the incumbent band is worth more than
        ``survey_weight`` every slot, as on an always-on carrier, no survey scan
        is ever taken and interception is untouched.
        """
        if self._hits[band] > 0:
            return 0.0
        return self._survey_weight * (1.0 - self._survey_duty) ** int(
            self._counts[band]
        )

    def upper_bound(self, slot: int, z: float = 1.0) -> NDArray[np.float64]:
        """Optimistic per-band occupancy, used to drive exploration."""
        values = np.empty(self._n_bands, dtype=np.float64)
        for band in range(self._n_bands):
            coupled = self._coupled_posterior(band, slot)
            if coupled is not None:
                mean, spread = coupled
                values[band] = mean + z * spread
                continue
            hits, observations = self._phase_evidence(band, slot)
            if observations <= 0.0:
                values[band] = 1.0
                continue
            mean, _ = self.posterior(band, slot)
            values[band] = (
                mean
                + self._wilson_half_width(hits, observations, z)
                + self._survey_bonus(band)
            )
            if (
                self._coupled_survey_counts is not None
                and band not in self._coupled_member_index
                and self._hits[band] == 0
                and self._counts[band] <= self._coupled_survey_counts[band]
            ):
                values[band] = 2.0
        return values

    def lower_bound(self, band: int, slot: int, z: float = 1.0) -> float:
        """Conservative occupancy for this band, used to gate an override."""
        mean, sd = self.posterior(band, slot)
        return max(0.0, mean - z * sd)

    def period(self, band: int) -> int | None:
        """Current period estimate for a band, or None if none is fitted."""
        return self._period[band]

    def coupled_period(self) -> int | None:
        return self._coupled_period

    def coupled_members(self) -> tuple[int, ...]:
        return self._coupled_members

    def counts(self) -> NDArray[np.int64]:
        """Per-band scan counts."""
        return self._counts.copy()

    def reset(self) -> None:
        """Clear all statistics for a new episode."""
        self._history.reset()
        self._counts[:] = 0
        self._hits[:] = 0
        self._since_refit[:] = 0
        self._period = [None] * self._n_bands
        self._obs_phase = [None] * self._n_bands
        self._hit_phase = [None] * self._n_bands
        self._long_candidates = [()] * self._n_bands
        self._coupled_period = None
        self._coupled_members = ()
        self._coupled_member_index = {}
        self._coupled_log_likelihood = None
        self._coupled_evidence = None
        self._coupled_survey_counts = None
        self._n00[:] = 9.0
        self._n01[:] = 1.0
        self._n11[:] = 9.0
        self._n10[:] = 1.0
        self._last_slot[:] = -1
        self._last_det[:] = False
