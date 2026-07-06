# Deployment

Three long-running pieces: the **backend** and **frontend** on the PC, the
**sensor** on the Pi. Running them in terminals means they die when the window
closes — deploy them as services instead.

Pick one API key and use it everywhere (or leave auth off and skip the key).

> **For a true 24/7 detector, run the backend on the always-on Pi instead of
> the PC** (see "Backend on the Pi" below). Then scoring, the anomaly layer,
> and attack alerts keep running with the PC off; you only need the PC to
> retrain models and to view the dashboard.

## Backend on the Pi (24/7, PC-independent — recommended)

Training stays on the PC (it's heavy); the Pi only *runs* the trained models
(cheap). One-time setup:

1. **Backend Python env on the Pi** (piwheels provides the ARM wheels):
   ```bash
   cd ~/nids-dashboard/backend
   python3 -m venv .venv
   .venv/bin/pip install --upgrade pip
   .venv/bin/pip install -r requirements.txt   # a few minutes on a Pi
   ```
2. **Copy the trained artifacts from the PC** (train there first). From the PC:
   ```powershell
   scp -r C:\Users\Luis\nids-dashboard\backend\data\processed luisa@<pi-ip>:~/nids-dashboard/backend/data/
   ```
   `data/processed/` holds the model + transformer + anomaly `.joblib` files
   and `cic_metrics.json` — everything the backend needs to score. (Optional:
   also copy `data/raw/KDDTest+.txt`, `KDDTrain+.txt`, and
   `data/processed/rules.csv` if you want the Metrics/Dataset/Rules panels to
   work on the Pi. Do **not** copy `data/raw/cic/` — it's ~840 MB and only
   needed for training.)
3. **Key + service:**
   ```bash
   sudo cp ~/nids-dashboard/deploy/nids-backend.env.example /etc/nids-backend.env
   sudo nano /etc/nids-backend.env        # set NIDS_API_KEY (+ alert vars)
   sudo chmod 600 /etc/nids-backend.env
   sudo cp ~/nids-dashboard/deploy/nids-backend.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now nids-backend
   curl -s http://127.0.0.1:8000/health
   ```
4. **Point the sensor at the local backend** (was the PC's IP):
   ```bash
   sudo sed -i 's#http://[0-9.]*:8000#http://127.0.0.1:8000#' \
        /etc/systemd/system/nids-sensor.service
   sudo systemctl daemon-reload && sudo systemctl restart nids-sensor
   ```
   (Running the sensor by hand instead? Just use `--url http://127.0.0.1:8000`.)

The anomaly baseline (`window_baseline.jsonl`) now accumulates on the Pi, so
train the anomaly model there too: `cd ~/nids-dashboard/backend &&
.venv/bin/python -m nids.anomaly train`, then
`sudo systemctl restart nids-backend`.

The dashboard is view-on-demand: run the frontend on the PC (or anywhere) with
`NEXT_PUBLIC_API_URL=http://<pi-ip>:8000`. With the PC off, scoring and alerts
keep running — you just can't open the dashboard until it's back.

## Backend (Windows PC, as a service via NSSM)

1. Persist the key so it survives reboots (admin PowerShell):
   ```powershell
   setx NIDS_API_KEY "your-key" /M
   ```
2. Install [NSSM](https://nssm.cc/download), then register uvicorn:
   ```powershell
   nssm install NIDS-Backend "C:\Users\Luis\nids-dashboard\backend\.venv\Scripts\python.exe" "-m uvicorn main:app --host 0.0.0.0 --port 8000"
   nssm set NIDS-Backend AppDirectory "C:\Users\Luis\nids-dashboard\backend"
   nssm start NIDS-Backend
   ```
3. Verify: `curl http://127.0.0.1:8000/health` returns JSON.

Firewall (once): `New-NetFirewallRule -DisplayName "NIDS API 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow` (admin).

## Frontend (Windows PC, production build)

```powershell
cd C:\Users\Luis\nids-dashboard\frontend
$env:NEXT_PUBLIC_API_URL = "http://10.20.20.194:8000"
npm run build
npm run start          # serves the dashboard on :3000
```
To run it as a service too: `nssm install NIDS-Frontend "C:\Program Files\nodejs\npm.cmd" "run start"` with `AppDirectory` set to `frontend` and the `NEXT_PUBLIC_API_URL` env var.

> If `NIDS_API_KEY` is set on the backend, the browser dashboard needs the key
> too or every panel 401s. Either leave auth off, or wire the key into the
> frontend client first.

## Sensor (Raspberry Pi, systemd service)

```bash
# key (must match the backend)
sudo cp ~/nids-dashboard/deploy/nids-sensor.env.example /etc/nids-sensor.env
sudo nano /etc/nids-sensor.env          # set NIDS_API_KEY
sudo chmod 600 /etc/nids-sensor.env

# install + enable the unit (edit paths/iface/url inside if they differ)
sudo cp ~/nids-dashboard/deploy/nids-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nids-sensor

# check it
systemctl status nids-sensor
journalctl -u nids-sensor -f            # live logs ([sent]/[stat] lines)
```

Updating after a `git pull`: `sudo systemctl restart nids-sensor`.
