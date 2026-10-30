"""Nmap Guardian - a local-only coursework dashboard for P2.

The application intentionally scans only 127.0.0.1. It does not exploit targets,
perform credential attacks, or apply firewall changes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
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
    "vuln": {
        "arguments": ["-sV", "--version-all"],
        "label": "CVE Vulnerability scan",
        "scope": "Detailed service banners with automated CVE analysis",
        "timeout": 120,
    },
}
DEVELOPMENT_PORTS = {3000, 5000, 8000, 8080}
DASHBOARD_PORT = 5000
# Automatic cleanup deliberately has a narrower scope than the manual guidance.
# It exists for a controlled coursework demonstration, not for managing Windows.
AUTO_STOP_PORTS = {3000, 8000, 8080}
DEVELOPMENT_PROCESS_NAMES = {"python", "pythonw", "node", "npm"}
WINDOWS_CORE_PORTS = {135, 139, 445, 3389}
WINDOWS_CORE_PROCESS_NAMES = {"system", "services", "svchost", "lsass", "wininit", "smss", "csrss"}
SAFE_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

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


def find_powershell() -> str | None:
    return shutil.which("powershell") or shutil.which("pwsh")


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
    powershell = find_powershell()
    if not powershell:
        return {}

    script = r"""
      $serviceMap = @{}
      Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -gt 0 } |
        Group-Object ProcessId |
        ForEach-Object { $serviceMap[[string]$_.Name] = @($_.Group.Name) -join ', ' }
      $rows = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
          port = $_.LocalPort
          address = $_.LocalAddress
          pid = $_.OwningProcess
          process = if ($process) { $process.ProcessName } else { $null }
          services = $serviceMap[[string]$_.OwningProcess]
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
                "services": str(row.get("services") or ""),
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

        # Parse any CVEs reported directly by Nmap scripts (vulners / vuln)
        script_cves = []
        for script in port.findall("script"):
            output = str(script.attrib.get("output", ""))
            for cve in re.findall(r"CVE-\d{4}-\d{4,7}", output, re.IGNORECASE):
                script_cves.append(cve.upper())

        ports.append(
            {
                "port": int(port.attrib["portid"]),
                "protocol": port.attrib.get("protocol", "tcp"),
                "service": service_data.get("name", "unknown"),
                "details": details or "No version information returned",
                "detected_cves": list(dict.fromkeys(script_cves)),
            }
        )
    return sorted(ports, key=lambda item: (item["protocol"], item["port"]))


CVE_DATABASE = {
    445: {
        "cve_id": "CVE-2017-0144",
        "name": "EternalBlue (MS17-010) / Remote Code Execution",
        "cvss": "9.8",
        "severity": "Critical",
        "summary": "Flaw in Microsoft SMBv1 protocol allowing unauthenticated remote code execution (WannaCry vector).",
        "linux_cmd": "sudo systemctl stop smbd && sudo ufw deny 445/tcp",
        "windows_cmd": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
        "update_cmd": "winget upgrade Microsoft.Windows.Update or install KB4012598",
    },
    139: {
        "cve_id": "CVE-2017-7494",
        "name": "SambaCry / NetBIOS File Sharing Vulnerability",
        "cvss": "9.8",
        "severity": "Critical",
        "summary": "Vulnerability in Samba / NetBIOS allowing remote code execution via exposed writable shares.",
        "linux_cmd": "sudo systemctl stop smbd nmbd && sudo ufw deny 139/tcp",
        "windows_cmd": "New-NetFirewallRule -DisplayName 'Block NetBIOS 139' -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block",
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade samba",
    },
    21: {
        "cve_id": "CVE-2011-2523",
        "name": "vsftpd / Insecure Cleartext FTP Service",
        "cvss": "8.5",
        "severity": "High",
        "summary": "FTP transmits login credentials and session data in unencrypted plaintext across the network.",
        "linux_cmd": "sudo systemctl stop vsftpd && sudo ufw deny 21/tcp",
        "windows_cmd": "Stop-Service -Name ftpsvc -ErrorAction SilentlyContinue",
        "update_cmd": "sudo apt update && sudo apt purge vsftpd",
    },
    23: {
        "cve_id": "CVE-2020-10188",
        "name": "Telnet Daemon Plaintext Remote Access",
        "cvss": "9.8",
        "severity": "Critical",
        "summary": "Telnet communicates in cleartext without encryption; prone to buffer overflows and credential theft.",
        "linux_cmd": "sudo systemctl stop inetd && sudo apt purge telnetd",
        "windows_cmd": "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient",
        "update_cmd": "sudo apt update && sudo apt install ssh",
    },
    3389: {
        "cve_id": "CVE-2019-0708",
        "name": "BlueKeep RDP Pre-Auth RCE",
        "cvss": "9.8",
        "severity": "Critical",
        "summary": "Wormable pre-authentication Remote Code Execution vulnerability in Microsoft Remote Desktop Protocol.",
        "linux_cmd": "sudo ufw deny 3389/tcp",
        "windows_cmd": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1",
        "update_cmd": "Install security update KB4499175 / Windows Update",
    },
    135: {
        "cve_id": "CVE-2003-0352",
        "name": "Windows RPC DCOM Buffer Overflow",
        "cvss": "8.5",
        "severity": "High",
        "summary": "Flaw in RPC DCOM service handling malformed messages; exploited historically by the Blaster worm.",
        "linux_cmd": "sudo ufw deny 135/tcp",
        "windows_cmd": "New-NetFirewallRule -DisplayName 'Block MSRPC 135' -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block",
        "update_cmd": "Apply monthly Windows cumulative security updates",
    },
    3306: {
        "cve_id": "CVE-2012-2122",
        "name": "MySQL Authentication Bypass / Remote Exposure",
        "cvss": "8.5",
        "severity": "High",
        "summary": "Exposed relational database listener allowing remote brute force or authentication circumvention.",
        "linux_cmd": "sudo systemctl stop mysql && sudo ufw deny 3306/tcp",
        "windows_cmd": "Stop-Service -Name MySQL -ErrorAction SilentlyContinue",
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade mysql-server",
    },
    5432: {
        "cve_id": "CVE-2018-1058",
        "name": "PostgreSQL Insecure Search Path",
        "cvss": "7.5",
        "severity": "High",
        "summary": "Database port open to network access without restrictive access controls in pg_hba.conf.",
        "linux_cmd": "sudo systemctl stop postgresql && sudo ufw deny 5432/tcp",
        "windows_cmd": "Stop-Service -Name postgresql* -ErrorAction SilentlyContinue",
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade postgresql",
    },
    8000: {
        "cve_id": "CVE-2021-41773",
        "name": "Unauthenticated Directory Traversal & Exposure",
        "cvss": "7.5",
        "severity": "Review",
        "summary": "Development HTTP server running without authentication or TLS. Leaks source code and local directory tree.",
        "linux_cmd": "sudo fuser -k 8000/tcp",
        "windows_cmd": "Stop-Process -Id <PID>",
        "update_cmd": "Bind server to 127.0.0.1 or terminate the test process",
    },
    8080: {
        "cve_id": "CVE-2021-41773",
        "name": "Unauthenticated HTTP Dev Server",
        "cvss": "7.5",
        "severity": "Review",
        "summary": "Secondary HTTP port exposing unauthenticated application endpoints or test server instances.",
        "linux_cmd": "sudo fuser -k 8080/tcp",
        "windows_cmd": "Stop-Process -Id <PID>",
        "update_cmd": "Bind server to 127.0.0.1 or terminate the test process",
    },
    3000: {
        "cve_id": "CWE-200",
        "name": "Development Server Information Disclosure",
        "cvss": "6.5",
        "severity": "Review",
        "summary": "Node.js / React dev server with active hot-reload or debugging sockets open to the network.",
        "linux_cmd": "sudo fuser -k 3000/tcp",
        "windows_cmd": "Stop-Process -Id <PID>",
        "update_cmd": "Configure HOST=127.0.0.1 or terminate when finished testing",
    },
}


def check_version_cve(details: str, service_name: str) -> dict | None:
    text = f"{service_name} {details}".lower()
    if "openssl" in text:
        return {
            "cve_id": "CVE-2014-0160",
            "name": "OpenSSL Heartbleed Vulnerability",
            "cvss": "7.5",
            "severity": "High",
            "summary": "TLS heartbeat read overrun allows stealing memory contents, passwords, and private keys.",
            "linux_cmd": "sudo apt update && sudo apt --only-upgrade install openssl",
            "windows_cmd": "winget upgrade OpenSSL",
            "update_cmd": "sudo apt update && sudo apt --only-upgrade install openssl",
        }
    if "apache" in text and ("2.4.49" in text or "2.4.50" in text):
        return {
            "cve_id": "CVE-2021-41773",
            "name": "Apache Path Traversal and RCE",
            "cvss": "9.8",
            "severity": "Critical",
            "summary": "Path traversal flaw in Apache HTTP Server 2.4.49/2.4.50 mapped to files outside docroot.",
            "linux_cmd": "sudo apt update && sudo apt install --only-upgrade apache2",
            "windows_cmd": "winget upgrade Apache.HttpServer",
            "update_cmd": "sudo apt update && sudo apt install --only-upgrade apache2",
        }
    return None


def correlate_cve(service: dict) -> dict | None:
    detected_cves = service.get("detected_cves", [])
    if detected_cves:
        cve_id = detected_cves[0]
        return {
            "cve_id": cve_id,
            "name": f"Nmap Script Detected Vulnerability ({cve_id})",
            "cvss": "8.0",
            "severity": "High",
            "summary": f"Nmap NSE script confirmed active vulnerability matching {cve_id}.",
            "linux_cmd": f"sudo apt update && sudo apt --only-upgrade install {service.get('service', 'package')}",
            "windows_cmd": f"winget upgrade {service.get('service', 'package')}",
            "update_cmd": f"sudo apt update && sudo apt --only-upgrade install {service.get('service', 'package')}",
        }
    return check_version_cve(service.get("details", ""), service.get("service", "")) or CVE_DATABASE.get(service.get("port"))


def is_dashboard_listener(port: int, owner: dict | None) -> bool:
    """Recognize the dashboard listener without trusting a development reloader PID.

    Flask's debug reloader can keep the listening socket in a parent process while
    the request handler runs in a child process.  A scan initiated by this app can
    therefore safely treat its fixed localhost port as expected even when the two
    PIDs differ.
    """
    return port == DASHBOARD_PORT


def auto_stop_eligibility(port: int, owner: dict | None) -> tuple[bool, str]:
    """Allow automatic cleanup only for a narrow, local test-server scenario."""
    if port == DASHBOARD_PORT:
        return False, "Port 5000 is reserved for the Nmap Guardian dashboard and is never stopped automatically."
    if not owner:
        return False, "No live local process owner could be verified for this port."

    process_name = str(owner.get("process", "")).lower()
    try:
        pid = int(owner.get("pid", 0))
    except (TypeError, ValueError):
        pid = 0

    if pid <= 4 or pid == os.getpid() or process_name in WINDOWS_CORE_PROCESS_NAMES:
        return False, "Windows core processes and the dashboard process are protected from automatic cleanup."
    if port not in AUTO_STOP_PORTS or process_name not in DEVELOPMENT_PROCESS_NAMES:
        return False, "Automatic cleanup is limited to verified Python or Node test servers on ports 3000, 8000, or 8080."
    return True, "Verified local development process."


def decision(label: str, tone: str, summary: str, steps: list[str]) -> dict:
    """Create an explicit, human-readable recommendation for one local service."""
    return {"label": label, "tone": tone, "summary": summary, "steps": steps}


def risk_for(service: dict, approved_ports: set[int], owner: dict | None = None) -> dict:
    port = service["port"]
    service_name = service["service"].lower()
    process_name = str((owner or {}).get("process", "")).lower()
    high_risk_terms = {"ms-wbt-server", "rdp", "ssh", "telnet", "mysql", "postgresql", "microsoft-ds", "netbios-ssn", "vnc"}
    development_terms = {"http", "http-alt", "http-proxy", "python", "httpserver"}

    if is_dashboard_listener(port, owner):
        return {
            "level": "Good",
            "reason": "This is the Nmap Guardian dashboard listening only on localhost while the application is running.",
            "action": "Keep it running while using the dashboard. It is protected from automatic cleanup.",
            "decision": decision(
                "Keep open",
                "keep",
                "This is this dashboard, not an unexpected service.",
                ["Do not stop port 5000 while using Nmap Guardian.", "Use the Python dependency check below if you want to review this app's packages."],
            ),
        }
    if port in approved_ports:
        return {
            "level": "Good",
            "reason": "This port is part of the approved baseline.",
            "action": "Keep it documented and confirm that the service is still needed.",
            "decision": decision(
                "Keep open (approved)",
                "keep",
                "You marked this service as expected on this computer.",
                ["Leave it open only while it is still needed.", "Rescan after any configuration or software change."],
            ),
        }
    if port == 135 or (process_name == "svchost" and "rpc" in str((owner or {}).get("services", "")).lower()):
        return {
            "level": "Review",
            "reason": "Windows RPC is a core operating-system service and is normally owned by svchost.",
            "action": "Keep the Windows service running. Do not kill svchost; review network firewall policy only if this computer is exposed to untrusted networks.",
            "decision": decision(
                "Keep Windows RPC",
                "keep",
                "Port 135 is normally required by Windows. Closing it by killing svchost can break Windows features.",
                ["Do not use Stop-Process on svchost or PID 712.", "If you use public or untrusted networks, use your approved Windows Firewall policy to limit inbound access.", "Rescan after a firewall-policy change; this local scan cannot prove Internet exposure."],
            ),
        }
    if port in {139, 445} or service_name in {"microsoft-ds", "netbios-ssn"}:
        return {
            "level": "Danger",
            "reason": "Windows file and printer sharing (SMB) can expose shared files if it is enabled where it is not needed.",
            "action": "Decide whether this PC needs file or printer sharing. If not, disable File and Printer Sharing through the approved Windows Firewall or sharing settings; do not kill System PID 4.",
            "decision": decision(
                "Decide about file sharing",
                "protect",
                "Close external SMB access if you do not share files or printers from this PC. Do not stop System / PID 4.",
                ["If you do not use Windows file or printer sharing, disable its inbound firewall group in Windows Security or ask your administrator.", "If you do use it, keep it restricted to trusted private networks and trusted devices.", "Rescan after the policy change and document the decision."],
            ),
        }
    if process_name in WINDOWS_CORE_PROCESS_NAMES:
        return {
            "level": "Review",
            "reason": "This listener is owned by a protected Windows process, so killing the PID is not a safe remediation.",
            "action": "Inspect the owner and related Windows service first. Change it only through the documented application or Windows service settings.",
            "decision": decision(
                "Investigate — do not kill",
                "investigate",
                "Windows owns this listener. First identify the related service; do not close it by terminating the process.",
                ["Use Inspect in PowerShell to record the PID and any service names.", "Look up the service in Windows Services before changing its startup or firewall policy.", "Rescan only after an authorised configuration change."],
            ),
        }
    can_auto_stop, _ = auto_stop_eligibility(port, owner)
    if can_auto_stop:
        return {
            "level": "Review",
            "reason": "This is a verified local Python or Node test server that was not approved in the baseline.",
            "action": "Stop it after your test and let Nmap Guardian create a verification scan.",
            "decision": decision(
                "Close after test",
                "close",
                "This development server is safe to stop when you have finished testing it.",
                ["Use Stop test process + verify below.", "Confirm that the new scan lists this port under Newly closed."],
            ),
        }
    if service_name in high_risk_terms or port in {22, 23, 3389, 3306, 5432, 5900, 445, 139}:
        return {
            "level": "Danger",
            "reason": "This unexpected service can provide remote access or expose sensitive data if left available unnecessarily.",
            "action": "Confirm that it is required. If not, stop the local service or restrict it with a reviewed firewall rule, then rescan.",
            "decision": decision(
                "Confirm or close",
                "protect",
                "Keep this service only if you recognize it and need it. Otherwise stop it from its own application or service settings.",
                ["Inspect the owner before making a change.", "If it is not required, stop or uninstall it through its documented settings.", "Use an approved firewall rule when the service must remain installed but should not accept inbound traffic."],
            ),
        }
    if service_name in development_terms or port in {80, 443, 8000, 8080, 3000, 5000}:
        return {
            "level": "Review",
            "reason": "This looks like an unapproved web or development service.",
            "action": "Stop it after testing, or configure it to listen only on 127.0.0.1. Then run a verification scan.",
            "decision": decision(
                "Close after test",
                "close",
                "This looks like a development service. It should not remain open when the test is finished.",
                ["If you own the application, stop it from its terminal or configuration.", "If it must stay on, bind it to 127.0.0.1 instead of every network interface.", "Rescan to confirm the intended result."],
            ),
        }
    return {
        "level": "Review",
        "reason": "This open port is not included in the approved baseline.",
        "action": "Identify the owning application, document the business need, and remove or restrict it if it is unnecessary.",
        "decision": decision(
            "Identify before changing",
            "investigate",
            "There is not enough evidence to safely close this port yet.",
            ["Inspect the process owner and service name.", "Keep it only if you recognize and need it; otherwise stop it from its own application settings.", "Add it to the baseline only after you make that decision."],
        ),
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
    """Return local remediation guidance and, for a test server, a tightly scoped auto action."""
    port = int(service["port"])
    owner = service.get("owner")
    inspect = inspect_port_command(port)
    cve = service.get("cve")
    process_name = str(owner.get("process", "")).lower() if owner else ""
    pid = int(owner["pid"]) if owner and owner.get("pid") else None
    can_auto_stop, eligibility_note = auto_stop_eligibility(port, owner)

    # Windows commands
    win_stop = f"Stop-Process -Id {pid}" if pid else None
    win_firewall = (
        f'New-NetFirewallRule -DisplayName "Nmap Guardian block TCP {port}" '
        f"-Direction Inbound -Protocol TCP -LocalPort {port} -Action Block"
    )

    # Linux (sudo) cross-platform equivalents
    linux_stop = f"sudo fuser -k {port}/tcp" if port in DEVELOPMENT_PORTS else f"sudo systemctl stop {service.get('service', 'service-name')}"
    linux_firewall = f"sudo ufw deny {port}/tcp"
    update_cmd = (cve or {}).get("update_cmd") or (cve or {}).get("linux_cmd") or f"sudo apt update && sudo apt --only-upgrade install {service.get('service', 'package')}"

    plan = {
        "inspect": inspect,
        "stop": win_stop,
        "firewall": win_firewall,
        "linux_stop": linux_stop,
        "linux_firewall": linux_firewall,
        "update_cmd": update_cmd,
        "auto_stop": can_auto_stop,
        "cve": cve,
        "notice": "Review the command before running. Use an elevated PowerShell window on Windows, or sudo on Linux.",
    }

    if port == DASHBOARD_PORT:
        plan["notice"] = "This is the Nmap Guardian dashboard port. It is expected while the dashboard is open and cannot be stopped from this page."
    elif owner and (port in DEVELOPMENT_PORTS or process_name in DEVELOPMENT_PROCESS_NAMES):
        plan["notice"] = (
            "A verified local test server can be stopped here and immediately rescanned. "
            "The automatic action is limited to Python or Node on ports 3000, 8000, or 8080."
            if can_auto_stop
            else f"This process can only be reviewed manually. {eligibility_note}"
        )
    elif port not in WINDOWS_CORE_PORTS and process_name not in WINDOWS_CORE_PROCESS_NAMES:
        plan["notice"] = "This creates a local inbound firewall rule. It requires an elevated PowerShell window (or sudo ufw on Linux) and does not stop the process."
    else:
        plan["notice"] = "This port may belong to a Windows core service. Do not stop it from this dashboard. Review the service owner and your firewall policy first."
    return plan


def inspect_port_command(port: int) -> str:
    """Build the fixed, read-only PowerShell inspection command for one local port."""
    return (
        f"Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction SilentlyContinue | "
        "ForEach-Object { $connection = $_; $p = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue; "
        "$s = tasklist /svc /fo csv /nh /fi \"PID eq $($connection.OwningProcess)\" 2>$null | ConvertFrom-Csv -Header ImageName,PID,Services; "
        "[PSCustomObject]@{LocalAddress=$connection.LocalAddress;LocalPort=$connection.LocalPort;OwningProcess=$connection.OwningProcess;"
        "Process=if($p){$p.ProcessName}else{'Unknown'};Services=if($s){$s.Services}else{''}} } | "
        "Format-Table -AutoSize | Out-String -Width 220"
    )


def run_port_inspection(port: int) -> tuple[str, str | None]:
    """Execute only the allowlisted local listener query and return its display output."""
    powershell = find_powershell()
    if not powershell:
        return "", "PowerShell was not found on this computer."

    command = inspect_port_command(port)
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return "", f"Could not run the local PowerShell inspection: {error}"

    if result.returncode:
        return "", (result.stderr or result.stdout or "PowerShell returned an error.").strip()
    output = result.stdout.strip()
    return output or f"No active local TCP listener was found on port {port}.", None


def python_audit_command() -> str:
    """Show the exact read-only dependency command used for this dashboard runtime."""
    return f'"{sys.executable}" -m pip list --outdated --format=json'


def pip_upgrade_command(package_name: str) -> str | None:
    """Create a copyable command only for a conventional Python distribution name."""
    if not SAFE_PACKAGE_NAME.fullmatch(package_name):
        return None
    return f'"{sys.executable}" -m pip install --upgrade {package_name}'


def run_python_dependency_audit() -> tuple[list[dict], str | None]:
    """Read package-update metadata without installing or changing anything."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return [], f"Could not start the Python dependency check: {error}"

    if result.returncode:
        detail = (result.stderr or result.stdout or "pip returned an error.").strip()
        return [], f"Python dependency check failed: {detail}"
    try:
        packages = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return [], "Python dependency check returned an unreadable response. Check the Python package index connection and try again."
    if not isinstance(packages, list):
        return [], "Python dependency check returned an unexpected response."

    audited = []
    for package in packages:
        name = str(package.get("name") or "")
        current = str(package.get("version") or "Unknown")
        latest = str(package.get("latest_version") or "Unknown")
        if not name:
            continue
        audited.append(
            {
                "name": name,
                "current": current,
                "latest": latest,
                "upgrade": pip_upgrade_command(name),
            }
        )
    return sorted(audited, key=lambda package: package["name"].lower()), None


def windows_update_status_command() -> str:
    """Describe the fixed, read-only Windows update evidence query."""
    return "Get-Service wuauserv; Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5"


def run_windows_update_status() -> tuple[dict, str | None]:
    """Read local Windows update evidence without starting a scan or installing anything."""
    powershell = find_powershell()
    if not powershell:
        return {}, "PowerShell was not found on this computer."

    script = r"""
      $update = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
      $config = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue
      $hotfixes = @(
        Get-HotFix -ErrorAction SilentlyContinue |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 5 @{Name='id';Expression={$_.HotFixID}}, @{Name='installedOn';Expression={if ($_.InstalledOn) {$_.InstalledOn.ToString('yyyy-MM-dd')} else {'Unknown'}}}, @{Name='description';Expression={$_.Description}}
      )
      [PSCustomObject]@{
        serviceStatus = if ($update) { $update.Status.ToString() } else { 'Not found' }
        startupType = if ($config) { $config.StartMode } else { 'Unknown' }
        hotfixes = $hotfixes
      } | ConvertTo-Json -Compress -Depth 4
    """
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {}, f"Could not check local Windows update evidence: {error}"

    if result.returncode:
        detail = (result.stderr or result.stdout or "PowerShell returned an error.").strip()
        return {}, f"Windows update evidence check failed: {detail}"
    try:
        status = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {}, "Windows update evidence check returned an unreadable response."
    if not isinstance(status, dict):
        return {}, "Windows update evidence check returned an unexpected response."
    hotfixes = status.get("hotfixes", [])
    if isinstance(hotfixes, dict):
        hotfixes = [hotfixes]
    status["hotfixes"] = hotfixes if isinstance(hotfixes, list) else []
    return status, None


def enrich_services(services: list[dict], listeners: dict[int, dict] | None = None) -> list[dict]:
    baseline = load_json(BASELINE_FILE, {"approved_ports": []})
    approved_ports = {int(port) for port in baseline.get("approved_ports", [])}
    listeners = listeners or {}
    enriched = []
    for service in services:
        owner = listeners.get(service["port"])
        cve = correlate_cve(service)
        if cve:
            service["cve"] = cve
        enriched_service = {**service, **risk_for(service, approved_ports, owner)}
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

    version_flag = "--version-all" if profile_name == "vuln" else "--version-light"
    command = [executable, "-sV", version_flag, *profile["arguments"], "-oX", "-", LOCAL_TARGET]
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
            f"nmap -sV {version_flag}"
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
    baseline = load_json(BASELINE_FILE, {"approved_ports": []})
    approved_ports = {int(port) for port in baseline.get("approved_ports", [])}
    # Keep scans produced by earlier dashboard versions viewable.
    for scan in history:
        scan.setdefault("score", exposure_score(scan.get("services", [])))
        scan.setdefault("changes", {"opened": [], "closed": [], "previous_scan": None})
        scan.setdefault("scan_mode", "quick")
        scan.setdefault("scan_label", SCAN_PROFILES["quick"]["label"])
        scan.setdefault("scan_scope", SCAN_PROFILES["quick"]["scope"])
        for service in scan.get("services", []):
            current_guidance = risk_for(service, approved_ports, service.get("owner"))
            service.setdefault("decision", current_guidance["decision"])
            # Plans are calculated at display time so outdated scans cannot keep
            # showing an unsafe action after the policy has changed.
            service["remediation"] = remediation_plan(service)
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


def save_scan(scan: dict) -> dict:
    """Add one local scan to history and calculate its before/after comparison."""
    history = scan_history()
    scan["changes"] = changes_from_previous(scan, history)
    history.insert(0, scan)
    save_json(HISTORY_FILE, history[:20])
    return scan


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
    save_scan(scan)
    return redirect(url_for("scan_detail", scan_id=scan["id"]))


@app.post("/scan/<scan_id>/remediate/<int:port>")
def remediate_test_process(scan_id: str, port: int):
    """Stop one verified local test process, then create a new verification scan.

    This route intentionally refuses system processes, firewall changes, port 5000,
    and anything except Python/Node test servers on the explicit demo ports.
    """
    source_scan = find_scan(scan_id)
    if not source_scan:
        abort(404)

    owner = local_listeners().get(port)
    allowed, reason = auto_stop_eligibility(port, owner)
    if not allowed or not owner:
        return render_template("error.html", message=f"Automatic cleanup was not run. {reason}"), 400

    powershell = find_powershell()
    if not powershell:
        return render_template("error.html", message="PowerShell was not found, so the verified test process was not stopped."), 500

    pid = int(owner["pid"])
    command = f"Stop-Process -Id {pid} -ErrorAction Stop"
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return render_template("error.html", message=f"The verified test process could not be stopped: {error}"), 500

    if result.returncode:
        detail = (result.stderr or result.stdout or "PowerShell returned an error.").strip()
        return render_template("error.html", message=f"The verified test process was not stopped. {detail}"), 500

    try:
        verification = scan_localhost(source_scan.get("scan_mode", "quick"))
    except RuntimeError as error:
        return render_template("error.html", message=f"The test process was stopped, but the verification scan could not run: {error}"), 500

    verification["remediation_result"] = {
        "port": port,
        "pid": pid,
        "process": owner["process"],
        "command": command,
        "message": "Verified local test process stopped. This is a new scan, not a live update of the earlier result.",
    }
    save_scan(verification)
    return redirect(url_for("scan_detail", scan_id=verification["id"]))


@app.post("/scan/<scan_id>/inspect/<int:port>")
def inspect_port(scan_id: str, port: int):
    """Run the fixed read-only listener command directly from the dashboard."""
    scan = find_scan(scan_id)
    if not scan:
        abort(404)

    output, error = run_port_inspection(port)
    inspection_result = {
        "port": port,
        "command": inspect_port_command(port),
        "output": output,
        "error": error,
    }
    return render_template(
        "scan.html",
        scan=scan,
        baseline=load_json(BASELINE_FILE, {"approved_ports": []}),
        inspection_result=inspection_result,
    ), 500 if error else 200


@app.post("/scan/<scan_id>/python-audit")
def python_dependency_audit(scan_id: str):
    """List out-of-date packages for this dashboard's Python interpreter without updating them."""
    scan = find_scan(scan_id)
    if not scan:
        abort(404)

    packages, error = run_python_dependency_audit()
    audit_result = {
        "command": python_audit_command(),
        "interpreter": sys.executable,
        "packages": packages,
        "error": error,
    }
    return render_template(
        "scan.html",
        scan=scan,
        baseline=load_json(BASELINE_FILE, {"approved_ports": []}),
        python_audit_result=audit_result,
    ), 500 if error else 200


@app.post("/scan/<scan_id>/windows-update-status")
def windows_update_status(scan_id: str):
    """Show local Windows update evidence; no update is downloaded or installed."""
    scan = find_scan(scan_id)
    if not scan:
        abort(404)

    status, error = run_windows_update_status()
    update_result = {
        "command": windows_update_status_command(),
        "status": status,
        "error": error,
    }
    return render_template(
        "scan.html",
        scan=scan,
        baseline=load_json(BASELINE_FILE, {"approved_ports": []}),
        windows_update_result=update_result,
    ), 500 if error else 200


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
