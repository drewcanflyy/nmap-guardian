# Nmap Guardian

## 1. Project in one sentence

**Nmap Guardian** is a local security dashboard that scans an authorized machine, explains exposed services, highlights unexpected ports, suggests safe remediation, and verifies the result with a second scan.

The project is designed for **P2 - Cartographie et services exposes** in the M111 mini-project brief.

## 2. The problem we solve

A machine can unintentionally expose a web server, database, remote-access tool, or development service. A user may see a list of ports from Nmap but not know:

- whether the service is expected;
- whether its exposure matters;
- what action to take;
- whether the action actually worked.

Nmap Guardian turns those technical scan results into a clear workflow:

```text
Discover -> Classify -> Explain -> Remediate -> Verify
```

## 3. Project scope and safety rules

For this coursework, the default target is **127.0.0.1 (localhost)**.
- Scan only localhost or a machine that the user explicitly owns or is authorized to test.
- Do not scan the university network, public IP addresses, or unknown devices.
- Do not exploit vulnerabilities or attempt password attacks.
- Any security action must show the user what will happen and require confirmation.
- Prefer stopping a local demo service or restricting it to localhost for the demonstration.

## 4. Main features

### A. Local scan

- Run Nmap against `127.0.0.1`.
- Detect open ports, protocol, service name, and version when available.
- Save the raw Nmap XML result as evidence.

### B. Service inventory

Present results in a simple table:

| Port | Protocol | Detected service | Expected? | Level | Recommended action |
| --- | --- | --- | --- | --- | --- |
| 8000 | TCP | Python HTTP server | No | Review | Stop after testing or bind only to localhost |

### C. Baseline comparison

The user can save an approved baseline of expected ports. A later scan is compared with it.

- New port found: alert.
- Port removed: record the change.
- Service/version changed: flag for review.

### D. Risk classification

Use transparent, rule-based levels instead of hidden decisions:

- **Good**: expected service and expected port.
- **Review**: service is open but is not in the approved baseline, or it is a development/test service.
- **Danger**: high-risk service exposed unexpectedly, such as remote administration or a database service. This is a prioritization label, not proof of a vulnerability.

Every label must say *why* it was assigned.

### E. Remediation guidance

For every finding, show:

- the reason the port needs attention;
- a safe manual action;
- the exact command only when it is appropriate for the local machine;
- a clear confirmation step before optional automation.

Examples:

- Stop a Python demo web server with `Ctrl+C` in its terminal.
- Change a development server to listen only on `127.0.0.1`.
- Review a local firewall rule before creating it.

### F. Verification scan

After a change, run Nmap again and display a before/after comparison. This is an important proof that risk reduction worked.

### G. Report export

Export HTML first (and PDF later if time permits) containing:

1. Target and authorization statement.
2. Tool versions and date/time.
3. Initial service inventory.
4. Findings and their classification rules.
5. Recommended or applied action.
6. Final scan and before/after evidence.
7. Limits of the test.

## 5. Technology choices

| Part | Choice | Why |
| --- | --- | --- |
| Language | Python | Required/allowed by the brief and easy to demo |
| Web dashboard | Flask | Small, simple, and sufficient for a local dashboard |
| Scanner | Nmap | Required by the P2 topic |
| Scan parsing | Nmap XML + Python standard library | Structured, reproducible results |
| Styling | Bootstrap or simple CSS | Fast, readable interface |
| Storage | JSON files or SQLite | Stores baseline and scan history locally |
| Reporting | HTML/CSS | Easy to inspect, print, and attach as evidence |

## 6. Do we need an AI API?

**No. An AI API is not needed for the project.**

The security classification should be predictable and explainable, so rule-based logic is better:

```text
IF a port is in the approved baseline -> Good
IF a port is new or runs a development service -> Review
IF a new port exposes remote administration or a database service -> Danger
```

This avoids API cost, internet dependency, privacy concerns, and unreliable explanations. If you want an optional future feature, an AI API could rewrite findings in simpler language, but it must never make security decisions or automatically run commands.

## 7. Build roadmap

### Phase 0 - Prepare the lab

1. Install Nmap.
2. Confirm `nmap --version` works in PowerShell.
3. Create a controlled local service for the demo:

   ```powershell
   python -m http.server 8000 --bind 127.0.0.1
   ```

4. Confirm the service manually in a browser at `http://127.0.0.1:8000`.

### Phase 1 - Prove the Nmap workflow

1. Scan localhost before launching the test service.
2. Start the test service.
3. Scan localhost again.
4. Stop the service with `Ctrl+C`.
5. Scan a third time.
6. Save all commands and results as project evidence.

Suggested safe command:

```powershell
nmap -sV -oX scan.xml 127.0.0.1
```

### Phase 2 - Build the minimum dashboard

1. Create a Flask app.
2. Add a **Scan localhost** button.
3. Run the predefined Nmap command from Python.
4. Parse the XML output.
5. Display ports and services in a table.

**Milestone:** the dashboard visibly lists the Python server on port 8000 while it is running.

### Phase 3 - Add security meaning

1. Add a JSON file containing approved ports.
2. Compare scan results with the baseline.
3. Add Good / Review / Danger badges.
4. Add a short explanation and remediation guide per finding.

**Milestone:** port 8000 is flagged as an unapproved development service when it is not in the baseline.

### Phase 4 - Before/after verification

1. Save a scan history.
2. Show newly opened and newly closed ports.
3. Add a **Rescan to verify** button.
4. Demonstrate that port 8000 disappears after the web service stops.

**Milestone:** a clear before/after comparison can be captured for the report.

### Phase 5 - Evidence and polish

1. Add scan date/time, Nmap version, target, and scope statement.
2. Export the findings as HTML.
3. Take annotated screenshots.
4. Write the risk section and the project limitations.

## 8. Demo scenario for the presentation

1. State the scope: only `127.0.0.1` is being tested.
2. Run a baseline scan with no demo service.
3. Launch the controlled Python server on port 8000.
4. Scan again through Nmap Guardian.
5. Show port 8000, the classification, and its explanation.
6. Stop the demo server through its terminal.
7. Rescan and show that port 8000 is closed.
8. Export the before/after report.

## 9. What to submit

- A technical report (the brief suggests 12-18 pages, excluding appendices).
- Service inventory table.
- Nmap commands and XML output files.
- Annotated screenshots before and after the change.
- Risk analysis: observation, interpretation, impact, and limit.
- Reduction actions and verification scan.
- A short presentation focused on 3-5 important results.

## 10. Limits to state honestly

- Nmap identifies exposure; it does not prove a service is vulnerable.
- Service/version detection can be incomplete or inaccurate.
- A localhost scan does not show how another network sees the machine.
- The tool only assesses the authorized target at the time of the scan.
- Severity labels are guidance based on documented rules, not a complete security audit.
