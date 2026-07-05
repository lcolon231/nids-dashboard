"""Alert aggregation, throttling, formatting, and config (Phase 12)."""
import pytest

from nids.alerts import AlertConfig, AlertNotifier


def notifier(sent, **cfg):
    config = AlertConfig(kind="generic", webhook_url="http://hook.test", **cfg)
    return AlertNotifier(config, sender=lambda t, m: sent.append((t, m)))


class TestConfig:
    def test_disabled_without_webhook(self):
        assert AlertConfig().enabled is False

    def test_webhook_enables(self):
        assert AlertConfig(webhook_url="http://x").enabled is True

    def test_email_needs_host_and_to(self):
        assert AlertConfig(kind="email", email_to="a@b.c").enabled is False
        assert AlertConfig(kind="email", email_to="a@b.c", smtp_host="smtp").enabled is True

    def test_from_env(self):
        cfg = AlertConfig.from_env({
            "NIDS_ALERT_KIND": "ntfy",
            "NIDS_ALERT_WEBHOOK": "https://ntfy.sh/mytopic",
            "NIDS_ALERT_COOLDOWN": "30",
            "NIDS_ALERT_MIN_ATTACKS": "3",
        })
        assert cfg.kind == "ntfy"
        assert cfg.cooldown == 30
        assert cfg.min_attacks == 3
        assert cfg.enabled

    def test_from_empty_env_is_disabled(self):
        assert AlertConfig.from_env({}).enabled is False


class TestThrottling:
    def test_below_threshold_does_not_send(self):
        sent = []
        n = notifier(sent, min_attacks=5)
        n.record_attacks(3)
        assert n.maybe_flush(now=100) is False
        assert sent == []

    def test_accumulates_until_threshold_crossed(self):
        sent = []
        n = notifier(sent, min_attacks=5)
        n.record_attacks(3)
        n.maybe_flush(now=100)          # 3 < 5, held
        n.record_attacks(4)             # total 7
        assert n.maybe_flush(now=101) is True
        assert len(sent) == 1
        assert "7 attack flows" in sent[0][1]

    def test_cooldown_suppresses_second_alert(self):
        sent = []
        n = notifier(sent, min_attacks=1, cooldown=60)
        n.record_attacks(10)
        assert n.maybe_flush(now=100) is True
        n.record_attacks(10)
        assert n.maybe_flush(now=130) is False   # only 30s later
        assert n.maybe_flush(now=161) is True     # cooldown elapsed
        assert len(sent) == 2

    def test_anomaly_always_alerts_regardless_of_min_attacks(self):
        sent = []
        n = notifier(sent, min_attacks=100)
        n.record_anomaly("10.0.0.66", 8.5, 999)
        assert n.maybe_flush(now=100) is True
        assert "anomalous" in sent[0][1]
        assert "10.0.0.66" in sent[0][1]

    def test_disabled_notifier_never_sends(self):
        sent = []
        n = AlertNotifier(AlertConfig(), sender=lambda t, m: sent.append((t, m)))
        n.record_attacks(1000)
        assert n.maybe_flush(now=100) is False
        assert sent == []

    def test_pending_resets_after_send(self):
        sent = []
        n = notifier(sent, min_attacks=1, cooldown=0)
        n.record_attacks(5, sources=["A"])
        n.maybe_flush(now=100)
        # nothing pending now; another flush with no new signal does nothing
        assert n.maybe_flush(now=200) is False
        assert len(sent) == 1


class TestFormatting:
    def test_summary_lists_sources(self):
        sent = []
        n = notifier(sent, min_attacks=1)
        n.record_attacks(2003, sources=["10.20.20.194"])
        n.maybe_flush(now=100)
        title, msg = sent[0]
        assert "2003 attack flows" in msg
        assert "10.20.20.194" in msg
        assert "🚨" in title

    def test_many_sources_truncated(self):
        sent = []
        n = notifier(sent, min_attacks=1)
        n.record_attacks(10, sources=[f"10.0.0.{i}" for i in range(6)])
        n.maybe_flush(now=100)
        assert "+3 more" in sent[0][1]


class TestForce:
    def test_force_sends_test_alert_even_when_empty(self):
        sent = []
        n = notifier(sent, min_attacks=100)
        assert n.maybe_flush(now=100, force=True) is True
        assert "test alert" in sent[0][1].lower()

    def test_dispatch_failure_counted_not_raised(self):
        def boom(t, m):
            raise RuntimeError("network down")

        n = AlertNotifier(AlertConfig(webhook_url="http://x"), sender=boom)
        n.record_attacks(100)
        # must not raise — scoring must never break because alerting failed
        assert n.maybe_flush(now=100, force=True) is True
        assert n.failures == 1
        assert n.sent_count == 0
