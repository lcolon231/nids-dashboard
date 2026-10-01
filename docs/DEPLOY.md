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
   nssm install NIDS-Backend "C:\path\to\nids-dashboard\backend\.venv\Scripts\python.exe" "-m uvicorn main:app --host 0.0.0.0 --port 8000"
   nssm set NIDS-Backend AppDirectory "C:\path\to\nids-dashboard\backend"
   nssm start NIDS-Backend
   ```
3. Verify: `curl http://127.0.0.1:8000/health` returns JSON.

Firewall (once): `New-NetFirewallRule -DisplayName "NIDS API 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow` (admin).

## Frontend (Windows PC, production build)

```powershell
cd C:\path\to\nids-dashboard\frontend
$env:NEXT_PUBLIC_API_URL = "http://<backend-host>:8000"
$env:NEXT_PUBLIC_NIDS_API_KEY = "your-key"   # only if the backend has NIDS_API_KEY set
npm run build
npm run start          # serves the dashboard on :3000
```
To run it as a service too: `nssm install NIDS-Frontend "C:\Program Files\nodejs\npm.cmd" "run start"` with `AppDirectory` set to `frontend` (build first — the `NEXT_PUBLIC_*` vars only matter at build time).

> Both `NEXT_PUBLIC_*` variables are baked in at build time — re-run
> `npm run build` after changing them. If the backend has `NIDS_API_KEY` set and
> the frontend was built without `NEXT_PUBLIC_NIDS_API_KEY`, every panel 401s.
> The key ends up in the browser bundle, so keep the dashboard on a trusted LAN.

## Sensor (Raspberry Pi, systemd service)

```bash
# key (must match the backend)
sudo cp ~/nids-dashboard/deploy/nids-sensor.env.example /etc/nids-sensor.env
sudo nano /etc/nids-sensor.env          # set NIDS_API_KEY
sudo chmod 600 /etc/nids-sensor.env

# install + enable the unit — edit WorkingDirectory/ExecStart first: the
# checked-in paths, --iface and --url are examples (match your Pi + backend IP)
sudo cp ~/nids-dashboard/deploy/nids-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nids-sensor

# check it
systemctl status nids-sensor
journalctl -u nids-sensor -f            # live logs ([sent]/[stat] lines)
```

Updating after a `git pull`: `sudo systemctl restart nids-sensor`.
