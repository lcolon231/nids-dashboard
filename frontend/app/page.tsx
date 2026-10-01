"use client";

import { useEffect, useState } from "react";
import { fetchHealth, Health } from "@/lib/api";
import AnomalyPanel from "@/components/AnomalyPanel";
import DatasetPanel from "@/components/DatasetPanel";
import LiveFeedPanel from "@/components/LiveFeedPanel";
import MetricsPanel from "@/components/MetricsPanel";
import RulesPanel from "@/components/RulesPanel";

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => setDown(true));
  }, []);

  return (
    <main className="max-w-5xl mx-auto p-6 flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "var(--text-primary)" }}>
            NIDS Dashboard
          </h1>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            Network intrusion detection on NSL-KDD + CIC-IDS2017 — NB · DT · RF · XGBoost · Apriori · IsolationForest
          </p>
        </div>
        <span
          className="text-xs px-2.5 py-1 rounded-full flex items-center gap-1.5"
          style={{ border: "1px solid var(--border)", color: "var(--text-secondary)" }}
        >
          <span
            className="inline-block w-2 h-2 rounded-full"
            style={{
              background: down
                ? "var(--status-critical)"
                : health
                  ? "var(--status-good)"
                  : "var(--text-muted)",
            }}
          />
          {down
            ? "API offline"
            : health
              ? `API ok · ${health.models_loaded.length} models`
              : "checking…"}
        </span>
      </header>

      <div className="grid gap-6 md:grid-cols-2">
        <MetricsPanel />
        <DatasetPanel />
        <RulesPanel />
        <LiveFeedPanel />
        <AnomalyPanel />
      </div>
    </main>
  );
}
