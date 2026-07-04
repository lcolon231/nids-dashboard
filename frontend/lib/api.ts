// Typed client for the NIDS FastAPI backend (port 8000).

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

export type Phase = "binary" | "multiclass";
export type Split = "train" | "test";
export type Dataset = "nsl" | "cic";

export interface Health {
  status: string;
  models_loaded: string[];
  transformer_loaded: boolean;
}

export interface MetricSet {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface MetricsResponse {
  phase: Phase;
  split: string;
  dataset: Dataset;
  metrics: { nb: MetricSet; dt: MetricSet; rf: MetricSet; xgb: MetricSet };
}

export interface DatasetSummary {
  split: Split;
  rows: number;
  cols: number;
  class_distribution: Record<string, number>;
  label_distribution: Record<string, number>;
}

export interface Rule {
  antecedents: string;
  consequents: string;
  support: number;
  confidence: number;
  lift: number;
}

export interface LiveEvent {
  ts: number;
  protocol_type: string | null;
  service: string | null;
  flag: string | null;
  // host-impact content features (NSL-KDD counts, not filenames)
  num_file_creations: number | null;
  num_access_files: number | null;
  num_shells: number | null;
  num_root: number | null;
  root_shell: number | null;
  num_compromised: number | null;
  hot: number | null;
  has_file_activity: boolean;
  prediction: number;
  label: string;
  is_attack: boolean;
}

export interface LiveRecent {
  count: number;
  attacks: number;
  events: LiveEvent[];
}

// Phase 11: per-source windowed anomaly detection.
export interface AnomalyWindow {
  src_ip: string;
  window_start: number;
  flow_count: number;
  distinct_dst_ports: number;
  distinct_dst_hosts: number;
  failed_ratio: number;
  ports_per_host: number;
  total_bytes: number;
  mean_bytes: number;
  anomaly_score: number;
  is_anomaly: boolean;
}

export interface AnomalyRecent {
  count: number;
  anomalies: number;
  windows: AnomalyWindow[];
}

export interface AnomalyStatus {
  model_loaded: boolean;
  window_seconds: number;
  baseline_windows_captured: number;
  windows_open: number;
}

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

export const fetchHealth = () => get<Health>("/health");
export const fetchMetrics = (phase: Phase, dataset: Dataset = "nsl") =>
  get<MetricsResponse>(`/metrics?phase=${phase}&dataset=${dataset}`);
export const fetchSummary = (split: Split) =>
  get<DatasetSummary>(`/dataset/summary?split=${split}`);
export const fetchRules = () => get<{ count: number; rules: Rule[] }>("/rules");
export const fetchLiveRecent = (limit = 50) =>
  get<LiveRecent>(`/live/recent?limit=${limit}`);
export const fetchAnomaliesRecent = (limit = 50) =>
  get<AnomalyRecent>(`/anomalies/recent?limit=${limit}`);
export const fetchAnomalyStatus = () => get<AnomalyStatus>("/anomalies/status");
