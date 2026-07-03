"use client";

import { useEffect, useState } from "react";
import { fetchLiveRecent, LiveRecent } from "@/lib/api";
import { LoadState, Panel } from "./Panel";

const POLL_MS = 2000;

export default function LiveFeedPanel() {
  const [data, setData] = useState<LiveRecent | null>(null);
  const [error, setError] = useState<string>();

  useEffect(() => {
    let alive = true;
    const tick = () =>
      fetchLiveRecent(50)
        .then((d) => alive && (setData(d), setError(undefined)))
        .catch((e) => alive && setError(String(e.message ?? e)));
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <Panel title="Live feed" subtitle="Sensor batches scored via /score/live (DT binary)">
      {!data ? (
        <LoadState error={error} />
      ) : data.events.length === 0 ? (
        <p className="text-xs py-6 text-center" style={{ color: "var(--text-muted)" }}>
          No live traffic yet — start the sensor: <code>python sensor_sim.py</code>
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {/* stat tiles */}
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg p-3" style={{ border: "1px solid var(--border)" }}>
              <div className="text-2xl font-semibold" style={{ color: "var(--text-primary)" }}>
                {data.count}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                recent records scored
              </div>
            </div>
            <div className="rounded-lg p-3" style={{ border: "1px solid var(--border)" }}>
              <div
                className="text-2xl font-semibold"
                style={{ color: data.attacks > 0 ? "var(--status-critical)" : "var(--text-primary)" }}
              >
                {data.attacks}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                flagged as attacks
              </div>
            </div>
          </div>
          {/* event list */}
          <ul className="flex flex-col text-xs" style={{ fontVariantNumeric: "tabular-nums" }}>
            {data.events.slice(0, 10).map((e, i) => (
              <li
                key={`${e.ts}-${i}`}
                className="py-1"
                style={{ borderTop: "1px solid var(--gridline)" }}
              >
                <div className="flex items-center gap-2">
                  <span style={{ color: "var(--text-muted)" }}>
                    {new Date(e.ts * 1000).toLocaleTimeString()}
                  </span>
                  <span className="flex-1 truncate" style={{ color: "var(--text-secondary)" }}>
                    {e.protocol_type}/{e.service} · {e.flag}
                  </span>
                  <span
                    className="font-semibold flex items-center gap-1"
                    style={{ color: e.is_attack ? "var(--status-critical)" : "var(--status-good)" }}
                  >
                    {e.is_attack ? "▲ attack" : "✓ normal"}
                  </span>
                </div>
                {e.is_attack && e.has_file_activity && (
                  <div
                    className="mt-0.5 inline-flex items-center gap-1 px-1.5 py-0.5 rounded"
                    style={{
                      border: "1px solid var(--border)",
                      color: "var(--text-secondary)",
                    }}
                    title="Host impact — file-activity counts reported by the sensor for this connection"
                  >
                    📁 {e.num_file_creations ?? 0} created · {e.num_access_files ?? 0} accessed
                    {(e.root_shell ?? 0) >= 1 && (
                      <span className="font-semibold" style={{ color: "var(--status-critical)" }}>
                        · root
                      </span>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}
