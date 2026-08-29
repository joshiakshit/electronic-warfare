import { describe, expect, it } from 'vitest'
import { demoAccount, environmentSummary, missionVerdict, performanceSeries, schedulerProfile, threatAssessment } from './viewUtils'
import type { SimulationResult } from './dashboardUtils'

const run = (interceptionRatio: number): SimulationResult => ({
  scheduler_name: 'test',
  track: 'blind',
  seed: 1,
  duration_seconds: 0.1,
  config: { n_bands: 1, n_slots: 1, k: 1, pfa: 0.01, detection_threshold: 4.6, dwell: 1, retune_cost_slots: 0, n_emitters: 0 },
  detector: { requested_pfa: 0.01, effective_pfa: 0.01, threshold: 4.6, dwell: 1, nominal_pd: 0.9 },
  metrics: {
    interception_ratio: interceptionRatio, intercept_rate: 0, interception_hits: 0, transmissions: 1,
    average_reward: 0, total_reward: 0, hit_reward: 0, miss_cost: 0, novelty_bonus: 0, revisit_decay: 0,
    retune_penalty: 0, mean_ttfi: 1, ttfi_penalized: 1, intercept_fraction: 1, pd: 1, pfa: 0,
    sensitivity: 1, evaluation_utility: 0, total_utility: 0, time_error: 0, time_error_penalized: 0,
    burst_interception_ratio: 1, n_bursts: 1, n_intercepted_bursts: 1,
  },
  detection_counts: { hits: 0, scans_on: 0, false_alarms: 0, scans_off: 1 },
  evaluation_counts: { true_positives: 0, false_negatives: 1, false_alarms: 0 },
  prediction: null,
  per_emitter: [],
  log: { n_slots: 1, n_bands: 1, truth: [[false]], actions: [[0]], detections: [[false]], retune_events: [false], settling_slots: [false], valid_slots: [true], per_slot_rewards: [0] },
})

describe('missionVerdict', () => {
  it('defines the demo operator account', () => {
    expect(demoAccount).toEqual({ name: 'Mission Operator', role: 'EW Analyst' })
  })

  it('returns useful comparison deltas for the mission header', () => {
    expect(missionVerdict(run(0.4), run(0.2), run(0.8))).toEqual({
      baselineDelta: 0.2,
      oracleGap: -0.4,
      activeRatio: 0.4,
    })
  })

  it('describes the active scheduling algorithm', () => {
    expect(schedulerProfile('sliding_window_ucb')).toEqual({
      label: 'Sliding-window UCB',
      advantage: 'Adapts to changing emitters by learning from a recent observation window.',
    })
  })

  it('formats an unknown scheduler without inventing an advantage', () => {
    expect(schedulerProfile('custom_scheduler')).toEqual({
      label: 'Custom scheduler',
      advantage: 'Custom scan scheduling strategy.',
    })
  })

  it('summarizes the simulation environment', () => {
    expect(environmentSummary('periodic_radar', run(0.4))).toEqual({
      scenario: 'Periodic radar',
      scale: '1 band × 1 slot',
      channels: '1 channel',
      emitters: '0 emitters',
      dwell: '1 slot dwell',
      retune: 'No retune delay',
    })
  })

  it('builds comparable percentage series for performance charts', () => {
    expect(performanceSeries(run(0.4), run(0.2), run(0.8))[0]).toEqual({
      label: 'Interception',
      active: 0.4,
      baseline: 0.2,
      oracle: 0.8,
    })
  })

  it('raises the threat posture when a priority emitter is poorly contained', () => {
    const result = run(0.4)
    result.metrics.interception_hits = 3
    result.metrics.transmissions = 10
    result.per_emitter = [{
      index: 0, band: 2, type: 'periodic_radar', threat: 0.9, snr: 12, pd: 0.5,
      pd_hits: 2, pd_scans_on: 4, interception_ratio: 0.3, interception_hits: 3,
      transmissions: 10, first_intercept_slot: 4, intercepted: true, mean_time_error: 1,
      mean_time_error_penalized: 1, burst_interception_ratio: 0.25, n_bursts: 4,
      n_intercepted_bursts: 1,
    }]

    expect(threatAssessment(result)).toEqual({
      posture: 'CRITICAL',
      missedTransmissions: 7,
      uncontainedEmitters: 1,
      highestSnr: 12,
      exposedBursts: 3,
    })
  })
})
