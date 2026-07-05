"""Outbound attack alerts (Phase 12).

When the backend flags attacks, this pushes a notification to a channel you
configure via environment variables — a phone push (ntfy.sh), a Discord/Slack
webhook, a generic JSON endpoint, or email. It is a no-op unless configured,
so the rest of the app is unaffected.

Critically, alerts are AGGREGATED and THROTTLED: a port scan produces thousands
of flagged flows, but you get at most one alert per cooldown window summarizing
them ("2003 attacks from 10.20.20.194 in the last 60s") rather than a buzz per
flow. Per-flow attacks must also cross a minimum count (so a single stray
false-positive flow doesn't alert); anomalous windows — already aggregated per
source — always alert.

Environment variables (all optional):
    NIDS_ALERT_KIND        ntfy | discord | slack | generic | email  (default ntfy)
    NIDS_ALERT_WEBHOOK     the URL to POST to (ntfy/discord/slack/generic)
    NIDS_ALERT_COOLDOWN    seconds between alerts               (default 60)
    NIDS_ALERT_MIN_ATTACKS per-flow attacks needed to alert     (default 5)
    # email only:
    NIDS_ALERT_EMAIL_TO / _SMTP_HOST / _SMTP_PORT / _SMTP_USER / _SMTP_PASSWORD
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage

DEFAULT_COOLDOWN = 60.0
DEFAULT_MIN_ATTACKS = 5
VALID_KINDS = ("ntfy", "discord", "slack", "generic", "email")


@dataclass
class AlertConfig:
    kind: str = "ntfy"
    webhook_url: str | None = None
    cooldown: float = DEFAULT_COOLDOWN
    min_attacks: int = DEFAULT_MIN_ATTACKS
    email_to: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None

    @classmethod
    def from_env(cls, env: dict | None = None) -> "AlertConfig":
        e = os.environ if env is None else env
        return cls(
            kind=(e.get("NIDS_ALERT_KIND") or "ntfy").lower(),
            webhook_url=e.get("NIDS_ALERT_WEBHOOK") or None,
            cooldown=float(e.get("NIDS_ALERT_COOLDOWN") or DEFAULT_COOLDOWN),
            min_attacks=int(e.get("NIDS_ALERT_MIN_ATTACKS") or DEFAULT_MIN_ATTACKS),
            email_to=e.get("NIDS_ALERT_EMAIL_TO") or None,
            smtp_host=e.get("NIDS_ALERT_SMTP_HOST") or None,
            smtp_port=int(e.get("NIDS_ALERT_SMTP_PORT") or 587),
            smtp_user=e.get("NIDS_ALERT_SMTP_USER") or None,
            smtp_password=e.get("NIDS_ALERT_SMTP_PASSWORD") or None,
        )

    @property
    def enabled(self) -> bool:
        if self.kind == "email":
            return bool(self.email_to and self.smtp_host)
        return bool(self.webhook_url)


def _new_pending() -> dict:
    return {"attacks": 0, "anomalies": 0, "sources": set(), "worst_score": 0.0, "worst_src": None}


class AlertNotifier:
    """Aggregates attack signals and dispatches throttled summary alerts.

    `sender(title, message)` performs the actual delivery; the default routes
    by config.kind. Tests inject a fake sender to capture alerts offline.
    """

    def __init__(self, config: AlertConfig, sender=None) -> None:
        self.config = config
        self._send = sender or self._dispatch
        self._pending = _new_pending()
        self._last_sent = 0.0
        self.sent_count = 0
        self.failures = 0

    # --- ingest ---------------------------------------------------------------
    def record_attacks(self, count: int, sources=()) -> None:
        if count <= 0:
            return
        self._pending["attacks"] += count
        self._pending["sources"].update(s for s in sources if s)

    def record_anomaly(self, src_ip: str, score: float, ports: int) -> None:
        p = self._pending
        p["anomalies"] += 1
        if src_ip:
            p["sources"].add(src_ip)
        if score > p["worst_score"]:
            p["worst_score"], p["worst_src"] = score, src_ip

    # --- dispatch -------------------------------------------------------------
    def maybe_flush(self, now: float, force: bool = False) -> bool:
        """Send a summary if there's something worth reporting and the cooldown
        has elapsed. Returns True if an alert was sent."""
        if not self.config.enabled:
            return False
        p = self._pending
        has_signal = p["anomalies"] > 0 or p["attacks"] >= self.config.min_attacks
        if not force and (not has_signal or now - self._last_sent < self.config.cooldown):
            return False
        if force and p["attacks"] == 0 and p["anomalies"] == 0:
            title, message = "NIDS test alert", "This is a test alert from your NIDS backend."
        else:
            title, message = self._format(p)
        try:
            self._send(title, message)
            self.sent_count += 1
        except Exception as exc:  # noqa: BLE001 — never let alerting break scoring
            self.failures += 1
            print(f"[warn] alert dispatch failed ({self.config.kind}): {exc!r}")
        self._last_sent = now
        self._pending = _new_pending()
        return True

    def _format(self, p: dict) -> tuple[str, str]:
        srcs = sorted(p["sources"])
        src_str = ", ".join(srcs[:3]) + (f" (+{len(srcs) - 3} more)" if len(srcs) > 3 else "")
        parts = []
        if p["attacks"]:
            parts.append(f"{p['attacks']} attack flows flagged")
        if p["anomalies"]:
            worst = f" (worst: {p['worst_src']} score {p['worst_score']:.2f})" if p["worst_src"] else ""
            parts.append(f"{p['anomalies']} anomalous source-window(s){worst}")
        title = "🚨 NIDS attack alert"
        message = "; ".join(parts)
        if src_str:
            message += f" — sources: {src_str}"
        return title, message

    def _dispatch(self, title: str, message: str) -> None:
        cfg = self.config
        if cfg.kind == "email":
            self._send_email(title, message)
            return
        url = cfg.webhook_url
        if cfg.kind == "ntfy":
            data = message.encode("utf-8")
            headers = {"Title": title, "Priority": "high", "Tags": "rotating_light"}
            self._http_post(url, data, headers)
        elif cfg.kind == "discord":
            self._http_post(url, json.dumps({"content": f"**{title}**\n{message}"}).encode(),
                            {"Content-Type": "application/json"})
        elif cfg.kind == "slack":
            self._http_post(url, json.dumps({"text": f"*{title}*\n{message}"}).encode(),
                            {"Content-Type": "application/json"})
        else:  # generic
            self._http_post(url, json.dumps({"title": title, "message": message}).encode(),
                            {"Content-Type": "application/json"})

    @staticmethod
    def _http_post(url: str, data: bytes, headers: dict) -> None:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — user-configured URL
            resp.read()

    def _send_email(self, title: str, message: str) -> None:
        cfg = self.config
        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = cfg.smtp_user or cfg.email_to
        msg["To"] = cfg.email_to
        msg.set_content(message)
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as s:
            s.starttls(context=ssl.create_default_context())
            if cfg.smtp_user:
                s.login(cfg.smtp_user, cfg.smtp_password or "")
            s.send_message(msg)

    def status(self) -> dict:
        return {
            "enabled": self.config.enabled,
            "kind": self.config.kind,
            "cooldown_seconds": self.config.cooldown,
            "min_attacks": self.config.min_attacks,
            "alerts_sent": self.sent_count,
            "dispatch_failures": self.failures,
        }
