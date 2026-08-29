export interface SimulationLog {
  n_slots: number;
  n_bands: number;
  truth: boolean[][];
  actions: number[][];
  detections: boolean[][];
  retune_events: boolean[];
  settling_slots: boolean[];
}

export interface SimulationMetrics {
  interception_ratio: number | null;
  average_reward: number | null;
  retune_penalty: number | null;
  mean_ttfi: number | null;
  pd: number | null;
  pfa: number | null;
}

export interface SimulationResult {
  scheduler_name: string;
  metrics: SimulationMetrics;
  log: SimulationLog;
}

export interface SimulationResponse {
  active: SimulationResult;
  baseline: SimulationResult;
  oracle: SimulationResult;
}

export interface ScenarioResponse {
  scenarios: string[];
}

export interface SchedulerResponse {
  schedulers: string[];
}

export async function fetchApi<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: string } | null;
    throw new Error(body?.detail ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}
