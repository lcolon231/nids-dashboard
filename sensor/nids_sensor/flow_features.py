"""CIC-IDS2017-style flow features (modern schema, Phase 10).

32 flow-metadata features — sizes, timings, direction, TCP flags — computable
from packet headers alone, so they work on encrypted traffic. Unlike the
NSL-KDD schema there are no cross-connection windows: every feature is
per-flow, computed at finalization from the Flow's running stats.

Durations and inter-arrival times are microseconds, matching CICFlowMeter.
Must stay identical to backend/nids/flowschema.py FLOW_FEATURES (a test
enforces this when the backend is checked out alongside).
"""
from __future__ import annotations

FLOW_FEATURES = [
    "dst_port",
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "tot_fwd_bytes",
    "tot_bwd_bytes",
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "bwd_pkt_len_max",
    "bwd_pkt_len_min",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "flow_bytes_per_s",
    "flow_pkts_per_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "fin_flag_cnt",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "ack_flag_cnt",
    "urg_flag_cnt",
    "down_up_ratio",
    "avg_pkt_size",
    "init_win_bytes_fwd",
    "init_win_bytes_bwd",
]
assert len(FLOW_FEATURES) == 32


def cic_features(flow) -> dict:
    """32-feature dict from a finalized Flow (see flows.Flow running stats)."""
    fwd, bwd = flow.fwd_len, flow.bwd_len
    duration_us = (flow.last_ts - flow.first_ts) * 1e6
    duration_s = duration_us / 1e6
    tot_pkts = fwd.count + bwd.count
    tot_bytes = fwd.total + bwd.total
    flags = flow.tcp_flag_counts

    record = {
        "dst_port": flow.dst_port,
        "flow_duration": int(duration_us),
        "tot_fwd_pkts": fwd.count,
        "tot_bwd_pkts": bwd.count,
        "tot_fwd_bytes": fwd.total,
        "tot_bwd_bytes": bwd.total,
        "fwd_pkt_len_max": fwd.max,
        "fwd_pkt_len_min": fwd.min,
        "fwd_pkt_len_mean": fwd.mean,
        "fwd_pkt_len_std": fwd.std,
        "bwd_pkt_len_max": bwd.max,
        "bwd_pkt_len_min": bwd.min,
        "bwd_pkt_len_mean": bwd.mean,
        "bwd_pkt_len_std": bwd.std,
        "flow_bytes_per_s": tot_bytes / duration_s if duration_s > 0 else 0.0,
        "flow_pkts_per_s": tot_pkts / duration_s if duration_s > 0 else 0.0,
        "flow_iat_mean": flow.flow_iat.mean,
        "flow_iat_std": flow.flow_iat.std,
        "flow_iat_max": flow.flow_iat.max,
        "flow_iat_min": flow.flow_iat.min,
        "fwd_iat_mean": flow.fwd_iat.mean,
        "bwd_iat_mean": flow.bwd_iat.mean,
        "fin_flag_cnt": flags.get("F", 0),
        "syn_flag_cnt": flags.get("S", 0),
        "rst_flag_cnt": flags.get("R", 0),
        "psh_flag_cnt": flags.get("P", 0),
        "ack_flag_cnt": flags.get("A", 0),
        "urg_flag_cnt": flags.get("U", 0),
        "down_up_ratio": bwd.count / fwd.count if fwd.count else 0.0,
        "avg_pkt_size": tot_bytes / tot_pkts if tot_pkts else 0.0,
        "init_win_bytes_fwd": flow.init_win_fwd,
        "init_win_bytes_bwd": flow.init_win_bwd,
    }
    return {col: record[col] for col in FLOW_FEATURES}
