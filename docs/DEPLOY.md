# Deployment

Three long-running pieces: the **backend** and **frontend** on the PC, the
**sensor** on the Pi. Running them in terminals means they die when the window
closes — deploy them as services instead.

Pick one API key and use it everywhere (or leave auth off and skip the key).

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
