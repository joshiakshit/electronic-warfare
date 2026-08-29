export type {
  SimulationLog,
  SimulationMetrics,
  SimulationResult,
  SimulationResponse,
} from './dashboardUtils';

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
