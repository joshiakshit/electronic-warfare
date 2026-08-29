export type MetricFormat = 'percent' | 'number' | 'integer'

export interface EmitterSummary {
  index: number
  band: number
  type: string
  threat: number | null
  snr: number | null
  pd: number | null
  pd_hits: number
  pd_scans_on: number
  interception_ratio: number | null
  interception_hits: number
  transmissions: number
  first_intercept_slot: number | null
  intercepted: boolean
  mean_time_error: number | null
  mean_time_error_penalized: number | null
  burst_interception_ratio: number | null
  n_bursts: number
  n_intercepted_bursts: number
}

export interface SimulationConfig {
  n_bands: number
  n_slots: number
  k: number
  pfa: number | null
  detection_threshold: number | null
  dwell: number
  retune_cost_slots: number
  n_emitters: number
}

export interface DetectorSummary {
  requested_pfa: number | null
  effective_pfa: number | null
  threshold: number | null
  dwell: number
  nominal_pd: number | null
}

export interface SimulationMetrics {
  interception_ratio: number | null
  intercept_rate: number | null
  interception_hits: number
  transmissions: number
  average_reward: number | null
  total_reward: number | null
  hit_reward: number | null
  miss_cost: number | null
  novelty_bonus: number | null
  revisit_decay: number | null
  retune_penalty: number | null
  mean_ttfi: number | null
  ttfi_penalized: number | null
  intercept_fraction: number | null
  pd: number | null
  pfa: number | null
  sensitivity: number | null
  evaluation_utility: number | null
  total_utility: number | null
  time_error: number | null
  time_error_penalized: number | null
  burst_interception_ratio: number | null
  n_bursts: number
  n_intercepted_bursts: number
}

export interface DetectionCounts {
  hits: number
  scans_on: number
  false_alarms: number
  scans_off: number
}

export interface PredictionSummary {
  accuracy: number | null
  percentage_correct: number | null
  predictor_present: boolean
  n_predictions: number
  n_correct: number
  coverage: number
  mean_confidence: number | null
  n_overrides: number
}

export interface SimulationLog {
  n_slots: number
  n_bands: number
  truth?: boolean[][]
  actions: number[][]
  detections: boolean[][]
  retune_events: boolean[]
  settling_slots: boolean[]
  valid_slots: boolean[]
  per_slot_rewards: number[]
  emitters?: Array<{ band: number; type: string; threat: number | null; snr: number | null }>
  emitter_truth?: boolean[][] | null
  emitter_bands?: number[][] | null
}

export interface SimulationResult {
  scheduler_name: string
  track: string
  seed: number
  duration_seconds: number | null
  config: SimulationConfig
  detector: DetectorSummary
  metrics: SimulationMetrics
  detection_counts: DetectionCounts
  evaluation_counts: { true_positives: number; false_negatives: number; false_alarms: number }
  prediction: PredictionSummary | null
  per_emitter: EmitterSummary[]
  log: SimulationLog
  learning?: {
    metric: string
    values: number[][]
  }
  arbitration?: {
    prediction_band: number[]
    prediction_confidence: number[]
    inner_action: number[][]
    executed_action: number[][]
    did_override: boolean[]
  }
}

export interface SimulationResponse {
  active: SimulationResult
  baseline: SimulationResult
  oracle: SimulationResult
}

export interface BandSummary {
  band: number
  scans: number
  detections: number
  occupancy: number
}

export interface LearningBandRow {
  band: number
  value: number
  scans: number
  detections: number
}

export interface OutcomeCounts {
  hits: number
  misses: number
  falseAlarms: number
  idle: number
}

export interface ComparisonRow {
  key: keyof SimulationMetrics
  label: string
  format: MetricFormat
  lowerIsBetter?: boolean
  active: number | null
  baseline: number | null
  oracle: number | null
  delta: number | null
}

export function formatMetric(value: number | null | undefined, format: MetricFormat): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return 'N/A'
  if (format === 'percent') return `${(value * 100).toFixed(1)}%`
  if (format === 'integer') return Math.round(value).toLocaleString()
  return value.toFixed(2)
}

export function outcomeCounts(result: SimulationResult, throughSlot = result.log.n_slots - 1): OutcomeCounts {
  const counts: OutcomeCounts = { hits: 0, misses: 0, falseAlarms: 0, idle: 0 }
  const truth = result.log.truth
  if (!truth) return counts

  result.log.actions.forEach((bands, slot) => {
    if (slot > throughSlot) return
    if (result.log.valid_slots[slot] === false) return
    bands.forEach((band, channel) => {
      const transmitting = truth[band]?.[slot] ?? false
      const detected = result.log.detections[slot]?.[channel] ?? false
      if (transmitting && detected) counts.hits += 1
      else if (transmitting) counts.misses += 1
      else if (detected) counts.falseAlarms += 1
      else counts.idle += 1
    })
  })
  return counts
}

export function bandSummaries(result: SimulationResult): BandSummary[] {
  return Array.from({ length: result.log.n_bands }, (_, band) => {
    let scans = 0
    let detections = 0
    result.log.actions.forEach((bands, slot) => {
      bands.forEach((scannedBand, channel) => {
        if (scannedBand === band) {
          scans += 1
          if (result.log.detections[slot]?.[channel]) detections += 1
        }
      })
    })
    const activeSlots = result.log.truth?.[band]?.filter(Boolean).length ?? 0
    return {
      band,
      scans,
      detections,
      occupancy: result.log.n_slots > 0 ? activeSlots / result.log.n_slots : 0,
    }
  })
}

export function learningBandRows(
  result: SimulationResult,
  throughSlot: number,
): LearningBandRow[] {
  if (!result.learning) return []
  const slot = Math.max(0, Math.min(throughSlot, result.learning.values.length - 1))
  const values = result.learning.values[slot]
  if (!values) return []

  const rows = values.map((value, band) => {
    let scans = 0
    let detections = 0
    result.log.actions.forEach((bands, actionSlot) => {
      if (actionSlot > slot || result.log.valid_slots[actionSlot] === false) return
      bands.forEach((scannedBand, channel) => {
        if (scannedBand !== band) return
        scans += 1
        if (result.log.detections[actionSlot]?.[channel]) detections += 1
      })
    })
    return { band, value, scans, detections }
  })

  return rows.sort((left, right) => right.value - left.value || left.band - right.band)
}

const comparisonDefinitions: Array<{
  key: keyof SimulationMetrics
  label: string
  format: MetricFormat
  lowerIsBetter?: boolean
}> = [
  { key: 'interception_ratio', label: 'Interception ratio', format: 'percent' },
  { key: 'intercept_rate', label: 'Intercept rate', format: 'percent' },
  { key: 'pd', label: 'Probability of detection', format: 'percent' },
  { key: 'pfa', label: 'False alarm rate', format: 'percent', lowerIsBetter: true },
  { key: 'mean_ttfi', label: 'Mean TTFI', format: 'number', lowerIsBetter: true },
  { key: 'average_reward', label: 'Average reward', format: 'number' },
  { key: 'retune_penalty', label: 'Retune penalty', format: 'number', lowerIsBetter: true },
  { key: 'burst_interception_ratio', label: 'Burst interception', format: 'percent' },
]

export function comparisonRows(
  active: SimulationResult,
  baseline: SimulationResult,
  oracle: SimulationResult,
): ComparisonRow[] {
  return comparisonDefinitions.map(definition => {
    const activeValue = active.metrics[definition.key] as number | null
    const baselineValue = baseline.metrics[definition.key] as number | null
    return {
      ...definition,
      active: activeValue,
      baseline: baselineValue,
      oracle: oracle.metrics[definition.key] as number | null,
      delta: activeValue !== null && baselineValue !== null ? activeValue - baselineValue : null,
    }
  })
}
