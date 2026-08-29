import type { SimulationResult } from './dashboardUtils'

export type DashboardView = 'live' | 'performance' | 'threats'

export const demoAccount = { name: 'Mission Operator', role: 'EW Analyst' }

export const dashboardViews: Array<{ key: DashboardView; label: string; shortLabel: string }> = [
  { key: 'live', label: 'Live scan', shortLabel: 'Live' },
  { key: 'performance', label: 'Performance', shortLabel: 'FOM' },
  { key: 'threats', label: 'Threats', shortLabel: 'Threats' },
]

const schedulerProfiles: Record<string, { label: string; advantage: string }> = {
  round_robin: { label: 'Round-robin', advantage: 'Provides predictable, even scan coverage across every band.' },
  uniform_random: { label: 'Uniform random', advantage: 'Explores every band without adding prior assumptions.' },
  prior_weighted: { label: 'Prior-weighted', advantage: 'Concentrates scan time on bands with higher known threat priority.' },
  oracle: { label: 'Oracle', advantage: 'Uses ground truth to establish the theoretical performance ceiling.' },
  ucb1: { label: 'UCB1', advantage: 'Balances exploration and exploitation with confidence bounds for each band.' },
  sliding_window_ucb: { label: 'Sliding-window UCB', advantage: 'Adapts to changing emitters by learning from a recent observation window.' },
  discounted_ucb: { label: 'Discounted UCB', advantage: 'Responds to changing activity by giving recent observations more weight.' },
  thompson_sampling: { label: 'Thompson sampling', advantage: 'Uses posterior uncertainty to explore bands in proportion to their likelihood of success.' },
  discounted_thompson: { label: 'Discounted Thompson sampling', advantage: 'Combines probability matching with faster adaptation to nonstationary emitters.' },
  belief: { label: 'Belief scheduler', advantage: 'Tracks latent emitter state and scans bands with the strongest activity belief.' },
  sniper: { label: 'Sniper', advantage: 'Reserves scan capacity for confident next-transmission predictions.' },
}

export function schedulerProfile(name: string) {
  return schedulerProfiles[name] ?? {
    label: name.replace(/_/g, ' ').replace(/^./, character => character.toUpperCase()),
    advantage: 'Custom scan scheduling strategy.',
  }
}

export function environmentSummary(scenario: string, result: SimulationResult) {
  const { config } = result
  const plural = (value: number, singular: string, pluralForm = `${singular}s`) => `${value.toLocaleString()} ${value === 1 ? singular : pluralForm}`
  return {
    scenario: scenario.replace(/_/g, ' ').replace(/^./, character => character.toUpperCase()),
    scale: `${plural(config.n_bands, 'band')} × ${plural(config.n_slots, 'slot')}`,
    channels: plural(config.k, 'channel'),
    emitters: plural(config.n_emitters, 'emitter'),
    dwell: `${plural(config.dwell, 'slot')} dwell`,
    retune: config.retune_cost_slots === 0 ? 'No retune delay' : `${plural(config.retune_cost_slots, 'slot')} retune delay`,
  }
}

export function missionVerdict(active: SimulationResult, baseline: SimulationResult, oracle: SimulationResult) {
  const activeRatio = active.metrics.interception_ratio
  const baselineRatio = baseline.metrics.interception_ratio
  const oracleRatio = oracle.metrics.interception_ratio
  return {
    activeRatio,
    baselineDelta: activeRatio !== null && baselineRatio !== null ? activeRatio - baselineRatio : null,
    oracleGap: activeRatio !== null && oracleRatio !== null ? activeRatio - oracleRatio : null,
  }
}

export function performanceSeries(active: SimulationResult, baseline: SimulationResult, oracle: SimulationResult) {
  return [
    { label: 'Interception', active: active.metrics.interception_ratio, baseline: baseline.metrics.interception_ratio, oracle: oracle.metrics.interception_ratio },
    { label: 'Detection', active: active.metrics.pd, baseline: baseline.metrics.pd, oracle: oracle.metrics.pd },
    { label: 'Burst capture', active: active.metrics.burst_interception_ratio, baseline: baseline.metrics.burst_interception_ratio, oracle: oracle.metrics.burst_interception_ratio },
  ]
}

export function threatAssessment(result: SimulationResult) {
  const missedTransmissions = Math.max(0, result.metrics.transmissions - result.metrics.interception_hits)
  const uncontainedEmitters = result.per_emitter.filter(emitter => (emitter.interception_ratio ?? 0) < 0.5).length
  const highestSnr = result.per_emitter.reduce<number | null>((highest, emitter) => emitter.snr === null ? highest : Math.max(highest ?? emitter.snr, emitter.snr), null)
  const exposedBursts = result.per_emitter.reduce((total, emitter) => total + Math.max(0, emitter.n_bursts - emitter.n_intercepted_bursts), 0)
  const critical = result.per_emitter.some(emitter => (emitter.threat ?? 0) >= 0.8 && (emitter.interception_ratio ?? 0) < 0.5)
  return {
    posture: critical ? 'CRITICAL' : uncontainedEmitters > 0 || missedTransmissions > 0 ? 'ELEVATED' : 'MONITORED',
    missedTransmissions,
    uncontainedEmitters,
    highestSnr,
    exposedBursts,
  }
}
