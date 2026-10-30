/* Nmap Guardian front-end
   Motion handles entry choreography. Everything else is native DOM. */

import { animate, inView } from "https://cdn.jsdelivr.net/npm/motion@14.8.0/+esm";

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const root = document.documentElement;

/* --------------------------------------------------------------------------
   Scan console (estimated progress, never pretends to be exact)
   -------------------------------------------------------------------------- */

const consoleEl = document.querySelector("#scan-progress");
const valueEl = document.querySelector("[data-scan-progress-value]");
const fillEl = document.querySelector("[data-scan-progress-fill]");
const messageEl = document.querySelector("[data-scan-progress-message]");
const trackEl = document.querySelector(".scan-console-track");

let progressTimer;

function setProgress(value, message) {
  const rounded = Math.max(0, Math.min(100, Math.round(value)));
  if (valueEl) valueEl.textContent = `${rounded}%`;
  if (fillEl) fillEl.style.width = `${rounded}%`;
  if (trackEl) trackEl.setAttribute("aria-valuenow", String(rounded));
  if (messageEl && message) messageEl.textContent = message;
}

function stageMessage(progress, mode) {
  if (progress < 16) return "Preparing Nmap and checking localhost.";
  if (progress < 50) return mode === "deep" ? "Walking all 65,535 local TCP ports." : "Identifying common local services.";
  if (progress < 82) return "Reading service banners and process owners.";
  return "Finishing the local scan.";
}

function beginScan(mode, firstMessage) {
  window.clearInterval(progressTimer);
  if (!consoleEl) return;

  const startedAt = performance.now();
  const expectedMs = mode === "deep" ? 165000 : mode === "vuln" ? 60000 : 16000;

  consoleEl.hidden = false;
  consoleEl.classList.remove("is-error");
  setProgress(3, firstMessage || stageMessage(3, mode));

  progressTimer = window.setInterval(() => {
    const fraction = Math.min(1, (performance.now() - startedAt) / expectedMs);
    const progress = 3 + 88 * (1 - Math.pow(1 - fraction, 1.7));
    setProgress(Math.min(91, progress), stageMessage(progress, mode));
  }, 280);
}

function finishScan(message) {
  window.clearInterval(progressTimer);
  setProgress(100, message || "Scan complete. Opening the new result.");
}

function failScan(message) {
  window.clearInterval(progressTimer);
  if (consoleEl) consoleEl.classList.add("is-error");
  setProgress(0, message);
}

/* --------------------------------------------------------------------------
   Form loading states
   -------------------------------------------------------------------------- */

function busy(button, text) {
  if (!button || button.disabled) return null;
  const label = button.querySelector(".button-label");
  const original = label ? label.textContent : null;
  button.disabled = true;
  button.classList.add("is-loading");
  if (label && text) label.textContent = text;
  return () => {
    button.disabled = false;
    button.classList.remove("is-loading");
    if (label && original) label.textContent = original;
  };
}

document.querySelectorAll("[data-scan-form]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const submitter = event.submitter || form.querySelector("button[type='submit']");
    const button = submitter || form.querySelector("button[type='submit']");
    if (!button || button.disabled) return;

    const mode = submitter?.value || form.querySelector("[name='scan_mode']")?.value || "quick";
    const label = button.querySelector(".button-label");
    const original = label ? label.textContent : null;
    const buttons = [...form.querySelectorAll("button[type='submit']")];

    buttons.forEach((item) => { item.disabled = true; });
    button.classList.add("is-loading");
    if (label) label.textContent = "Scanning";
    beginScan(mode);

    try {
      const data = new FormData(form);
      if (submitter?.name) data.set(submitter.name, submitter.value);

      const response = await fetch(form.action, { method: "POST", body: data });

      if (!response.ok) {
        failScan("The scan did not complete. Opening the error details.");
        window.setTimeout(() => window.location.assign(response.url), 700);
        return;
      }

      finishScan();
      window.setTimeout(() => window.location.assign(response.url), reduceMotion ? 0 : 320);
    } catch {
      failScan("Could not reach the local dashboard. Check that the Flask server is still running, then retry.");
      buttons.forEach((item) => { item.disabled = false; });
      button.classList.remove("is-loading");
      if (label && original) label.textContent = original;
    }
  });
});

document.querySelectorAll("[data-python-audit-form]").forEach((form) => {
  form.addEventListener("submit", () => {
    busy(form.querySelector("button[type='submit']"), "Checking packages");
  });
});

document.querySelectorAll("[data-windows-update-form]").forEach((form) => {
  form.addEventListener("submit", () => {
    busy(form.querySelector("button[type='submit']"), "Reading updates");
  });
});

document.querySelectorAll("[data-inspection-form]").forEach((form) => {
  form.addEventListener("submit", () => {
    busy(form.querySelector("button[type='submit']"), "Inspecting owner");
  });
});

document.querySelectorAll("[data-stop-form]").forEach((form) => {
  form.addEventListener("submit", () => {
    busy(form.querySelector("button[type='submit']"), "Stopping");
    beginScan("quick", "Stopping the verified test process, then scanning again.");
  });
});

/* --------------------------------------------------------------------------
   Findings drawers
   -------------------------------------------------------------------------- */

const findings = [...document.querySelectorAll("[data-finding]")];

function setDrawer(finding, open) {
  const toggle = finding.querySelector(".drawer-toggle");
  const label = toggle?.querySelector(".toggle-label");
  finding.classList.toggle("is-open", open);
  if (toggle) toggle.setAttribute("aria-expanded", String(open));
  if (label) label.textContent = open ? "Hide" : "Remediation";
}

findings.forEach((finding) => {
  const toggle = finding.querySelector(".drawer-toggle");
  if (!toggle) return;

  toggle.addEventListener("click", () => {
    const willOpen = !finding.classList.contains("is-open");
    if (willOpen) findings.forEach((other) => { if (other !== finding) setDrawer(other, false); });
    setDrawer(finding, willOpen);
  });

  finding.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !finding.classList.contains("is-open")) return;
    setDrawer(finding, false);
    toggle.focus();
  });
});

/* --------------------------------------------------------------------------
   Copy to clipboard
   -------------------------------------------------------------------------- */

document.querySelectorAll("[data-copy-command]").forEach((button) => {
  button.addEventListener("click", async () => {
    const command = button.dataset.copyCommand;
    if (!command) return;

    const original = button.textContent;
    try {
      if (!navigator.clipboard) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(command);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    window.setTimeout(() => { button.textContent = original; }, 1400);
  });
});

/* --------------------------------------------------------------------------
   Entry choreography
   -------------------------------------------------------------------------- */

if (!reduceMotion) {
  root.classList.add("has-motion");

  document.querySelectorAll("[data-intro]").forEach((element, index) => {
    element.classList.add("is-in");
    animate(
      element,
      { opacity: [0, 1], transform: ["translateY(16px)", "translateY(0px)"] },
      { duration: 0.62, delay: index * 0.05, ease: [0.16, 1, 0.3, 1] }
    );
  });

  document.querySelectorAll("[data-intro-card]").forEach((element, index) => {
    element.classList.add("is-in");
    animate(
      element,
      { opacity: [0, 1], transform: ["translateY(20px) scale(0.99)", "translateY(0px) scale(1)"] },
      { duration: 0.7, delay: 0.1 + index * 0.05, ease: [0.16, 1, 0.3, 1] }
    );
  });

  document.querySelectorAll("[data-reveal]").forEach((element) => {
    inView(
      element,
      () => {
        if (element.classList.contains("is-in")) return;
        element.classList.add("is-in");
        animate(
          element,
          { opacity: [0, 1], transform: ["translateY(14px)", "translateY(0px)"] },
          { duration: 0.6, ease: [0.16, 1, 0.3, 1] }
        );
      },
      { amount: 0.12 }
    );
  });
}
