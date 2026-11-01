# SENTINEL

Advanced Network Security & Intelligence Platform — a local Security Operations Center dashboard with an authorized TCP connect scanner.

SENTINEL only scans **localhost** and **private IPv4** ranges (RFC1918). Public internet scanning is rejected. Use it only on systems you are allowed to test.

## Requirements

- Windows 10/11
- Python 3.10 or later
- Visual Studio Code (optional)

## Install and run (PowerShell)

```powershell
cd C:\Users\pawar\OneDrive\Desktop\portscanner2\SENTINEL
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If `py` is unavailable, replace `py -3` with `python`.

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

Open: [http://127.0.0.1:5000](http://127.0.0.1:5000)

The SQLite database is created automatically at `instance/sentinel.db` on first launch.

## Environment variables

| Variable | Purpose | Local default |
| --- | --- | --- |
| `SENTINEL_SECRET_KEY` | Flask session/CSRF secret | `dev-sentinel-change-in-production` |
| `DATABASE_URL` | SQLAlchemy URI | `sqlite:///.../instance/sentinel.db` |
| `SENTINEL_COOKIE_SECURE` | Set `1` only behind HTTPS | `0` |

Example:

```powershell
$env:SENTINEL_SECRET_KEY = "replace-with-a-long-random-string"
python app.py
```

## First use

1. Register a full name, username, email, and password.
2. Sign in.
3. Open **Network Scanner**.
4. Target `127.0.0.1` (or another private IP you own).
5. Confirm authorization, then launch the scan.
6. Review results, history, analytics, and CSV export.

## Scanner limits

- TCP connect probes only (`socket.connect_ex`)
- IPv4 localhost / private addresses only
- Maximum 4096 ports per scan
- Operator authorization checkbox required
- Each user sees only their own records

## Project layout

```
SENTINEL/
  app.py
  config.py
  models.py
  scanner.py
  requirements.txt
  templates/
  static/
  instance/
```
