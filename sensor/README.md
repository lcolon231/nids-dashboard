# NIDS Pi Sensor

A real packet-capture sensor for the NIDS dashboard, built to run on a
Raspberry Pi (or any Linux box). It replaces `backend/sensor_sim.py`: instead
of replaying KDDTest+ rows, it sniffs live traffic, assembles packets into
connections, derives NSL-KDD's 41 features, and POSTs batches to the backend's
`/score/live` — the same API contract as the simulator, so the backend and
dashboard need no changes.

```
packets (scapy) ──► FlowTracker ──► FeatureBuilder ──► LiveScoreSender ──► POST /score/live
                    5-tuple flows,   2s window +        batches of 10,
                    TCP state -> flag  last-100-conn stats  retry on failure
```

## Install (on the Pi)

```bash
cd sensor
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run

Packet capture needs root (or `CAP_NET_RAW`):

```bash
sudo .venv/bin/python -m nids_sensor --iface eth0 --url http://<backend-host>:8000
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | `http://127.0.0.1:8000` | backend API base URL |
| `--iface` | scapy default | interface to sniff (e.g. `eth0`, `wlan0`) |
| `--bpf` | *(none)* | BPF capture filter; IP frames are filtered in software by default. Set e.g. `ip` to filter in the kernel — but some interfaces (Pi `wlan0`) silently drop all packets when a BPF filter is set with an unknown link type |
| `--batch` | 10 | records per POST |
| `--flush-interval` | 2.0 | max seconds before a partial batch is sent |
| `--idle-timeout` | 30.0 | idle seconds before an open TCP flow finalizes |
| `--schema` | `nsl` | feature schema + backend model family: `nsl` (41 NSL-KDD features) or `cic` (32 modern flow features) |

**Which schema?** `--schema cic` is the better fit for real traffic: its 32
features (packet sizes, inter-arrival times, TCP flag counts, init windows)
are all honestly derivable from headers, so nothing is zero-filled and the
models were trained on 2017 traffic rather than 1998. Requires the backend to
have run `python -m nids.models train --dataset cic`. `--schema nsl` scores
against the original NSL-KDD models.

To avoid needing `sudo` every time:

```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
```

To see more than the Pi's own traffic, mirror a switch port to the Pi's
interface, or run the Pi as the network gateway/AP.

## What's derived vs. approximated

- **Derived faithfully:** duration, protocol, service (port map), `flag` via a
  simplified Bro/Zeek TCP state machine (SF, S0, REJ, RSTO, RSTR, SH, OTH, …),
  src/dst bytes, land, urgent, the 2-second-window traffic features
  (`count`, `serror_rate`, …) and last-100-connection host features
  (`dst_host_*`).
- **Approximated:** the service map is a subset of the 1998 /etc/services
  table (unknown ports → `private`, which one-hot encodes to zeros for names
  the model never saw); `wrong_fragment` counts fragmented packets rather
  than verifying fragment correctness.
- **Not derivable — emitted as 0:** the 13 content features (`hot`,
  `logged_in`, `num_file_creations`, `num_failed_logins`, …). These came from
  host-side audit data in the original DARPA setup. A future host agent
  (auditd/Wazuh) or Zeek file extraction could fill them.

The caveats above apply to the default NSL-KDD schema, whose models are
trained on 1998-era simulated traffic. **`--schema cic` avoids both
problems** — no zero-filled content features and 2017-era training data —
though even CIC-IDS2017 is lab traffic, so treat live scores as a strong demo
rather than production detection.

## Tests

Pure-Python core (no root, no capture; scapy tests auto-skip if it isn't
installed):

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```
