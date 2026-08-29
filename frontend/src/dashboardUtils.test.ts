import { describe, expect, it } from 'vitest'
import {
  bandSummaries,
  comparisonRows,
  formatMetric,
  learningBandRows,
  outcomeCounts,
  type SimulationResult,
} from './dashboardUtils'

const defaultMetrics = {
  interception_ratio: 0.5,
  intercept_rate: 0.5,
  interception_hits: 1,
  transmissions: 2,
  average_reward: 0.25,
  total_reward: 1,
  hit_reward: 1,
  miss_cost: -1,
  novelty_bonus: 0,
  revisit_decay: 0,
  retune_penalty: -1,
  mean_ttfi: 2,
  ttfi_penalized: 2,
  intercept_fraction: 1,
  pd: 0.75,
  pfa: 0,
  sensitivity: 12,
  evaluation_utility: 2,
  total_utility: 2,
  time_error: 1,
  time_error_penalized: 1,
  burst_interception_ratio: 0.5,
  n_bursts: 2,
  n_intercepted_bursts: 1,
}

const result = (overrides: Partial<SimulationResult> = {}): SimulationResult => {
  const { metrics: overrideMetrics, ...otherOverrides } = overrides
  return {
  scheduler_name: 'ucb1',
  track: 'blind',
  seed: 42,
  duration_seconds: null,
  config: { n_bands: 3, n_slots: 4, k: 1, pfa: 0.01, detection_threshold: 4.6, dwell: 1, retune_cost_slots: 0, n_emitters: 0 },
  detector: {
    requested_pfa: 0.01,
    effective_pfa: 0.01,
    threshold: 4.6,
    dwell: 1,
    nominal_pd: 0.9,
  },
  detection_counts: { hits: 3, scans_on: 4, false_alarms: 1, scans_off: 5 },
  evaluation_counts: { true_positives: 1, false_negatives: 1, false_alarms: 0 },
  per_emitter: [],
  prediction: null,
  log: {
    n_slots: 4,
    n_bands: 3,
    truth: [[true, false, false, false], [false, true, false, false], [false, false, false, false]],
    actions: [[0], [1], [2], [0]],
    detections: [[true], [false], [false], [false]],
    retune_events: [false, true, true, true],
    settling_slots: [false, false, true, false],
    valid_slots: [true, true, false, true],
    per_slot_rewards: [1, -1, 0, 0],
  },
    ...otherOverrides,
    metrics: { ...defaultMetrics, ...overrideMetrics },
  }
}

describe('dashboardUtils', () => {
  it('formats percentages and unavailable values', () => {
    expect(formatMetric(0.456, 'percent')).toBe('45.6%')
    expect(formatMetric(null, 'percent')).toBe('N/A')
    expect(formatMetric(3.14159, 'number')).toBe('3.14')
  })

  it('counts hit, miss, false alarm, and idle scan outcomes', () => {
    expect(outcomeCounts(result())).toEqual({ hits: 1, misses: 1, falseAlarms: 0, idle: 1 })
  })

  it('counts outcomes only through the current playback slot', () => {
    expect(outcomeCounts(result(), 0)).toEqual({ hits: 1, misses: 0, falseAlarms: 0, idle: 0 })
    expect(outcomeCounts(result(), 1)).toEqual({ hits: 1, misses: 1, falseAlarms: 0, idle: 0 })
  })

  it('builds per-band scan summaries', () => {
    expect(bandSummaries(result())).toEqual([
      { band: 0, scans: 2, detections: 1, occupancy: 0.25 },
      { band: 1, scans: 1, detections: 0, occupancy: 0.25 },
      { band: 2, scans: 1, detections: 0, occupancy: 0 },
    ])
  })

  it('calculates comparison deltas against the baseline', () => {
    const active = result()
    const baseline = result({ scheduler_name: 'round_robin', metrics: { ...active.metrics, pd: 0.5 } })
    const rows = comparisonRows(active, baseline, result({ scheduler_name: 'oracle' }))
    expect(rows.find(row => row.key === 'pd')?.delta).toBe(0.25)
  })

  it('ranks learned band values at the selected slot', () => {
    const learned = result({
      learning: {
        metric: 'posterior_mean',
        values: [[0.2, 0.5, 0.1], [0.7, 0.4, 0.2]],
      },
    })

    expect(learningBandRows(learned, 1)).toEqual([
      { band: 0, value: 0.7, scans: 1, detections: 1 },
      { band: 1, value: 0.4, scans: 1, detections: 0 },
      { band: 2, value: 0.2, scans: 0, detections: 0 },
    ])
  })

  it('returns no learning rows for fixed schedulers', () => {
    expect(learningBandRows(result(), 1)).toEqual([])
  })
})
