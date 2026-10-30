"""Nmap Guardian - a local-only coursework dashboard for P2.

The application intentionally scans only 127.0.0.1. It does not exploit targets,
perform credential attacks, or apply firewall changes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, url_for

APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = APP_ROOT / "data"
HISTORY_FILE = DATA_DIR / "scan_history.json"
BASELINE_FILE = APP_ROOT / "baseline.json"
LOCAL_TARGET = "127.0.0.1"
SCAN_PROFILES = {
    "quick": {
        "arguments": [],
        "label": "Standard local scan",
        "scope": "Common TCP ports with service detection",
        "timeout": 60,
    },
    "deep": {
        "arguments": ["-p-"],
        "label": "Deep local TCP scan",
        "scope": "All 65,535 local TCP ports with lightweight service detection",
        "timeout": 240,
    },
}
DEVELOPMENT_PORTS = {3000, 5000, 8000, 8080}
WINDOWS_CORE_PORTS = {135, 139, 445, 3389}
WINDOWS_CORE_PROCESS_NAMES = {"system", "services", "svchost", "lsass", "wininit", "smss", "csrss"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "local-coursework-dashboard-not-for-production"


def iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def find_nmap() -> str | None:
    return shutil.which("nmap") or shutil.which("nmap.exe")


def nmap_version() -> str:
    executable = find_nmap()
    if not executable:
        return "Nmap not found"
    try:
        result = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
        return result.stdout.splitlines()[0] if result.stdout else "Nmap detected"
    except (OSError, subprocess.SubprocessError):
        return "Nmap detected (version unavailable)"


def local_listeners() -> dict[int, dict]:
    """Map local listening TCP ports to their owning Windows process when available.

    This inspection is read-only. It never terminates a process or changes a firewall rule.
    """
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return {}

    script = r"""
      $rows = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
          port = $_.LocalPort
          address = $_.LocalAddress
          pid = $_.OwningProcess
          process = if ($process) { $process.ProcessName } else { $null }
        }
      }
      $rows | ConvertTo-Json -Compress
    """
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode or not result.stdout.strip():
            return {}
        rows = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}

    if isinstance(rows, dict):
        rows = [rows]
    listeners: dict[int, dict] = {}
    for row in rows:
        try:
            port = int(row["port"])
            pid = int(row["pid"])
        except (KeyError, TypeError, ValueError):
            continue
        # IPv4 and IPv6 can produce duplicate rows for the same process and port.
        listeners.setdefault(
            port,
            {
                "pid": pid,
                "process": str(row.get("process") or "Unknown process"),
                "address": str(row.get("address") or "Unknown address"),
            },
        )
    return listeners


def parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    ports: list[dict] = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        service_data = service.attrib if service is not None else {}
        pieces = [
            service_data.get("product", ""),
            service_data.get("version", ""),
            service_data.get("extrainfo", ""),
        ]
        details = " ".join(piece for piece in pieces if piece).strip()
        ports.append(
            {
                "port": int(port.attrib["portid"]),
                "protocol": port.attrib.get("protocol", "tcp"),
                "service": service_data.get("name", "unknown"),
                "details": details or "No version information returned",
            }
        )
    return sorted(ports, key=lambda item: (item["protocol"], item["port"]))


def risk_for(service: dict, approved_ports: set[int]) -> dict:
    port = service["port"]
    service_name = service["service"].lower()
    high_risk_terms = {"ms-wbt-server", "rdp", "ssh", "telnet", "mysql", "postgresql", "microsoft-ds", "netbios-ssn", "vnc"}
    development_terms = {"http", "http-alt", "http-proxy", "python", "httpserver"}

    if port in approved_ports:
        return {
            "level": "Good",
            "reason": "This port is part of the approved baseline.",
            "action": "Keep it documented and confirm that the service is still needed.",
        }
    if service_name in high_risk_terms or port in {22, 23, 3389, 3306, 5432, 5900, 445, 139}:
        return {
            "level": "Danger",
            "reason": "This unexpected service can provide remote access or expose sensitive data if left available unnecessarily.",
            "action": "Confirm that it is required. If not, stop the local service or restrict it with a reviewed firewall rule, then rescan.",
        }
    if service_name in development_terms or port in {80, 443, 8000, 8080, 3000, 5000}:
        return {
            "level": "Review",
            "reason": "This looks like an unapproved web or development service.",
            "action": "Stop it after testing, or configure it to listen only on 127.0.0.1. Then run a verification scan.",
        }
    return {
        "level": "Review",
        "reason": "This open port is not included in the approved baseline.",
        "action": "Identify the owning application, document the business need, and remove or restrict it if it is unnecessary.",
    }


def exposure_score(services: list[dict]) -> dict:
    """Return an explainable priority score, not a vulnerability score."""
    counts = {"Good": 0, "Review": 0, "Danger": 0}
    for service in services:
        counts[service["level"]] = counts.get(service["level"], 0) + 1
    score = max(0, 100 - (counts["Review"] * 12) - (counts["Danger"] * 35))
    label = "Controlled" if score >= 85 else "Needs review" if score >= 60 else "Action needed"
    return {"value": score, "label": label, "counts": counts}


def remediation_plan(service: dict) -> dict:
    """Return manual, local-only commands. The website never executes these commands."""
    port = int(service["port"])
    owner = service.get("owner")
    inspect = (
        f"Get-NetTCPConnection -State Listen -LocalPort {port} | "
        "Select-Object LocalAddress,LocalPort,OwningProcess"
    )
    plan = {
        "inspect": inspect,
        "stop": None,
        "firewall": None,
        "notice": "Review the command before running it in an elevated PowerShell window.",
    }
    process_name = str(owner.get("process", "")).lower() if owner else ""
    if owner and (port in DEVELOPMENT_PORTS or process_name in {"python", "pythonw", "node", "npm"}):
        plan["stop"] = f"Stop-Process -Id {int(owner['pid'])}"
        plan["notice"] = "This stop command is offered only for a likely local development process. Save your work first."
    elif port not in WINDOWS_CORE_PORTS and process_name not in WINDOWS_CORE_PROCESS_NAMES:
        plan["firewall"] = (
            f'New-NetFirewallRule -DisplayName "Nmap Guardian block TCP {port}" '
            f"-Direction Inbound -Protocol TCP -LocalPort {port} -Action Block"
        )
        plan["notice"] = "This creates a local inbound firewall rule. It requires an elevated PowerShell window and does not stop the process."
    else:
        plan["notice"] = "This port may belong to a Windows core service. Do not stop it from this dashboard. Review the service owner and your firewall policy first."
    return plan


def enrich_services(services: list[dict], listeners: dict[int, dict] | None = None) -> list[dict]:
    baseline = load_json(BASELINE_FILE, {"approved_ports": []})
    approved_ports = {int(port) for port in baseline.get("approved_ports", [])}
    listeners = listeners or {}
    enriched = []
    for service in services:
        owner = listeners.get(service["port"])
        enriched_service = {**service, **risk_for(service, approved_ports)}
        if owner:
            enriched_service["owner"] = owner
        enriched_service["remediation"] = remediation_plan(enriched_service)
        enriched.append(enriched_service)
    return enriched


def scan_localhost(profile_name: str = "quick") -> dict:
    executable = find_nmap()
    if not executable:
        raise RuntimeError("Nmap was not found. Install it and make sure nmap is available in PATH.")
    profile = SCAN_PROFILES.get(profile_name)
    if not profile:
        raise RuntimeError("The requested scan profile is not available.")

    command = [executable, "-sV", "--version-light", *profile["arguments"], "-oX", "-", LOCAL_TARGET]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=profile["timeout"], check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"The scan timed out after {profile['timeout']} seconds.") from error
    except OSError as error:
        raise RuntimeError(f"Could not run Nmap: {error}") from error

    if not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or "Nmap did not return XML output.")
    try:
        services = enrich_services(parse_nmap_xml(result.stdout), local_listeners())
    except ET.ParseError as error:
        raise RuntimeError("Nmap returned output that could not be parsed as XML.") from error

    return {
        "id": str(uuid.uuid4())[:8],
        "timestamp": iso_now(),
        "target": LOCAL_TARGET,
        "command": (
            "nmap -sV --version-light"
            + (" " + " ".join(profile["arguments"]) if profile["arguments"] else "")
            + " -oX - 127.0.0.1"
        ),
        "nmap_version": nmap_version(),
        "scan_mode": profile_name,
        "scan_label": profile["label"],
        "scan_scope": profile["scope"],
        "services": services,
        "score": exposure_score(services),
        "raw_xml": result.stdout,
    }


def scan_history() -> list[dict]:
    history = load_json(HISTORY_FILE, [])
    # Keep scans produced by earlier dashboard versions viewable.
    for scan in history:
        scan.setdefault("score", exposure_score(scan.get("services", [])))
        scan.setdefault("changes", {"opened": [], "closed": [], "previous_scan": None})
        scan.setdefault("scan_mode", "quick")
        scan.setdefault("scan_label", SCAN_PROFILES["quick"]["label"])
        scan.setdefault("scan_scope", SCAN_PROFILES["quick"]["scope"])
        for service in scan.get("services", []):
            service.setdefault("remediation", remediation_plan(service))
    return history


def changes_from_previous(scan: dict, history: list[dict]) -> dict:
    if not history:
        return {"opened": [], "closed": [], "previous_scan": None}
    previous = history[0]
    now_ports = {item["port"] for item in scan["services"]}
    old_ports = {item["port"] for item in previous["services"]}
    return {
        "opened": sorted(now_ports - old_ports),
        "closed": sorted(old_ports - now_ports),
        "previous_scan": previous,
    }


def find_scan(scan_id: str) -> dict | None:
    return next((item for item in scan_history() if item["id"] == scan_id), None)


@app.get("/")
def index():
    history = scan_history()
    baseline = load_json(BASELINE_FILE, {"approved_ports": []})
    return render_template(
        "index.html",
        latest=history[0] if history else None,
        history=history[:6],
        nmap_available=bool(find_nmap()),
        nmap_version=nmap_version(),
        baseline=baseline,
    )


@app.post("/scan")
def run_scan():
    profile_name = request.form.get("scan_mode", "quick")
    try:
        scan = scan_localhost(profile_name)
    except RuntimeError as error:
        return render_template("error.html", message=str(error)), 500
    history = scan_history()
    scan["changes"] = changes_from_previous(scan, history)
    history.insert(0, scan)
    save_json(HISTORY_FILE, history[:20])
    return redirect(url_for("scan_detail", scan_id=scan["id"]))


@app.get("/scan/<scan_id>")
def scan_detail(scan_id: str):
    scan = find_scan(scan_id)
    if not scan:
        abort(404)
    return render_template("scan.html", scan=scan, baseline=load_json(BASELINE_FILE, {"approved_ports": []}))


@app.get("/scan/<scan_id>/report")
def report(scan_id: str):
    scan = find_scan(scan_id)
    if not scan:
        abort(404)
    return render_template("report.html", scan=scan)


@app.post("/baseline")
def update_baseline():
    """Save only user-selected port numbers from an existing local scan."""
    selected_ports = sorted({int(port) for port in request.form.getlist("approved_ports") if port.isdigit()})
    source_scan = request.form.get("source_scan", "")
    save_json(BASELINE_FILE, {"approved_ports": selected_ports, "updated_at": iso_now(), "note": "Approved locally in Nmap Guardian."})
    if source_scan and find_scan(source_scan):
        return redirect(url_for("scan_detail", scan_id=source_scan))
    return redirect(url_for("index"))


@app.get("/guidance")
def guidance():
    return render_template("guidance.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
