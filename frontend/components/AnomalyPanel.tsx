"use client";

import { useEffect, useState } from "react";
import {
  AnomalyRecent,
  AnomalyStatus,
  fetchAnomaliesRecent,
  fetchAnomalyStatus,
} from "@/lib/api";
import { LoadState, Panel } from "./Panel";

const POLL_MS = 2000;

export default function AnomalyPanel() {
  const [data, setData] = useState<AnomalyRecent | null>(null);
  const [status, setStatus] = useState<AnomalyStatus | null>(null);
  const [error, setError] = useState<string>();

  useEffect(() => {
    let alive = true;
    const tick = () =>
      Promise.all([fetchAnomaliesRecent(50), fetchAnomalyStatus()])
        .then(([d, s]) => alive && (setData(d), setStatus(s), setError(undefined)))
        .catch((e) => alive && setError(String(e.message ?? e)));
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const subtitle = status
    ? status.model_loaded
      ? `Per-source windows scored · ${status.window_seconds}s window`
      : `Baseline: ${status.baseline_windows_captured} windows captured — model not trained yet`
    : "Per-source windowed anomaly detection";

  return (
    <Panel title="Anomalies" subtitle={subtitle}>
      {!data ? (
        <LoadState error={error} />
      ) : !status?.model_loaded ? (
        <p className="text-xs py-6 text-center" style={{ color: "var(--text-muted)" }}>
          Capturing a normal-traffic baseline. Once enough windows are logged, run{" "}
          <code>python -m nids.anomaly train</code> and restart the API to start
          flagging deviations.
        </p>
      ) : data.windows.length === 0 ? (
        <p className="text-xs py-6 text-center" style={{ color: "var(--text-muted)" }}>
          No windows scored yet — waiting for the sensor.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg p-3" style={{ border: "1px solid var(--border)" }}>
              <div className="text-2xl font-semibold" style={{ color: "var(--text-primary)" }}>
                {data.count}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                recent source-windows
              </div>
            </div>
            <div className="rounded-lg p-3" style={{ border: "1px solid var(--border)" }}>
              <div
                className="text-2xl font-semibold"
                style={{ color: data.anomalies > 0 ? "var(--status-critical)" : "var(--text-primary)" }}
              >
                {data.anomalies}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                flagged anomalous
              </div>
            </div>
          </div>
          <ul className="flex flex-col text-xs" style={{ fontVariantNumeric: "tabular-nums" }}>
            {data.windows.slice(0, 10).map((w, i) => (
              <li
                key={`${w.src_ip}-${w.window_start}-${i}`}
                className="flex items-center gap-2 py-1"
                style={{ borderTop: "1px solid var(--gridline)" }}
              >
                <span className="w-28 truncate" style={{ color: "var(--text-secondary)" }}>
                  {w.src_ip}
                </span>
                <span className="flex-1 truncate" style={{ color: "var(--text-muted)" }}>
                  {w.distinct_dst_ports}p/{w.distinct_dst_hosts}h · {(w.failed_ratio * 100).toFixed(0)}% fail
                </span>
                <span
                  className="font-semibold"
                  style={{ color: w.is_anomaly ? "var(--status-critical)" : "var(--status-good)" }}
                >
                  {w.is_anomaly ? `▲ ${w.anomaly_score.toFixed(2)}` : "✓"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}
