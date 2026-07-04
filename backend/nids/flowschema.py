"""Modern flow-metadata feature schema (CIC-IDS2017).

32 features chosen so the SAME schema is (a) selectable from the published
CIC-IDS2017 MachineLearningCVE CSVs and (b) computable live by the Pi sensor
from packet headers alone — sizes, timings, direction, TCP flags — which is
what makes them usable on modern encrypted traffic. Durations and IATs are
in microseconds, matching CICFlowMeter's units.

The sensor keeps its own copy of FLOW_FEATURES (sensor/nids_sensor/
flow_features.py); a sensor test asserts the two stay identical.
"""
from __future__ import annotations

# Our snake_case name -> column name in the CIC CSVs (after whitespace strip).
CIC_COLUMN_MAP: dict[str, str] = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "tot_fwd_bytes": "Total Length of Fwd Packets",
    "tot_bwd_bytes": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_bytes_per_s": "Flow Bytes/s",
    "flow_pkts_per_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_mean": "Fwd IAT Mean",
    "bwd_iat_mean": "Bwd IAT Mean",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "avg_pkt_size": "Average Packet Size",
    "init_win_bytes_fwd": "Init_Win_bytes_forward",
    "init_win_bytes_bwd": "Init_Win_bytes_backward",
}

FLOW_FEATURES: list[str] = list(CIC_COLUMN_MAP)
assert len(FLOW_FEATURES) == 32

# --- labels -------------------------------------------------------------------
# CIC-IDS2017 attack labels -> 7 categories. "Web Attack" labels are matched
# by prefix because the raw CSVs contain an encoding-mangled dash in them.
CIC_CATEGORIES = ["benign", "dos", "portscan", "bruteforce", "webattack", "botnet", "other"]
CIC_CATEGORY_TO_INT = {name: i for i, name in enumerate(CIC_CATEGORIES)}

_EXACT = {
    "BENIGN": "benign",
    "DDoS": "dos",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "PortScan": "portscan",
    "FTP-Patator": "bruteforce",
    "SSH-Patator": "bruteforce",
    "Bot": "botnet",
    "Infiltration": "other",
    "Heartbleed": "other",
}


def cic_category(label: str) -> str:
    """Map a raw CIC-IDS2017 Label value to one of CIC_CATEGORIES."""
    label = label.strip()
    if label in _EXACT:
        return _EXACT[label]
    if label.startswith("Web Attack"):
        return "webattack"
    raise ValueError(f"unknown CIC-IDS2017 label: {label!r}")
