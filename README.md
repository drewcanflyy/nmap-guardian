# Nmap Guardian

Nmap Guardian is a local-only Flask dashboard for the **Cartographie et services exposés** coursework project. It uses Nmap to inventory exposed services on `127.0.0.1`, explain unexpected ports, provide safe manual remediation guidance, and verify the result with a subsequent scan.

> The application is intentionally locked to localhost. Do not modify it to scan networks or systems without explicit authorization.

## Features

- Standard scan for common local TCP ports.
- Deep scan for all 65,535 local TCP ports.
- Nmap XML parsing with service and version details when available.
- Good, Review, and Danger findings with explainable rules.
- Approved-port baseline management.
- Exposure score and scan-to-scan change tracking.
- Windows process and PID association for detected local listening ports.
- Copyable PowerShell command plans for inspection, controlled development-service stopping, or reviewed firewall blocking.
- Printable HTML report and Arabic project guide.

## Safety model

- The target is fixed to `127.0.0.1`.
- The dashboard never executes remediation commands itself.
- Windows core services and sensitive ports do not receive direct stop commands.
- A finding is an exposure observation, not proof of a vulnerability.

## Run locally

```powershell
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

Nmap must be installed and available in `PATH`.

## Controlled demonstration

```powershell
python -m http.server 8000 --bind 127.0.0.1
```

1. Run a scan and observe port 8000.
2. Stop the demo server with `Ctrl+C`.
3. Rescan and verify that the port appears under newly closed ports.

## Documentation

- [Project roadmap](PROJECT_ROADMAP.md)
- [Arabic project guide](PROJECT_GUIDE_AR.md)

## Technology

Python, Flask, Nmap, PowerShell `Get-NetTCPConnection`, JSON, GSAP, and Motion.
