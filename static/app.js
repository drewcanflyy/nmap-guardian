/* Motion is the modern evolution of Framer Motion. GSAP handles page-level choreography. */
import { animate, inView, stagger } from "https://cdn.jsdelivr.net/npm/motion@14.8.0/+esm";

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const scanProgress = document.querySelector("#scan-progress");
const scanProgressValue = document.querySelector("[data-scan-progress-value]");
const scanProgressFill = document.querySelector("[data-scan-progress-fill]");
const scanProgressMessage = document.querySelector("[data-scan-progress-message]");
const scanProgressTrack = document.querySelector(".scan-progress-track");

let progressTimer;

function setScanProgress(value, message) {
  const rounded = Math.max(0, Math.min(100, Math.round(value)));
  if (scanProgressValue) scanProgressValue.textContent = `${rounded}%`;
  if (scanProgressFill) scanProgressFill.style.width = `${rounded}%`;
  if (scanProgressTrack) scanProgressTrack.setAttribute("aria-valuenow", String(rounded));
  if (scanProgressMessage && message) scanProgressMessage.textContent = message;
}

function stageMessage(progress, mode) {
  if (progress < 18) return "Preparing Nmap and checking localhost…";
  if (progress < 52) return mode === "deep" ? "Checking local TCP ports…" : "Identifying common local services…";
  if (progress < 83) return "Reading service information and process owners…";
  return "Finishing the local scan…";
}

function beginScanProgress(mode) {
  window.clearInterval(progressTimer);
  if (!scanProgress) return;

  const startedAt = performance.now();
  // These values are deliberately estimates. Nmap does not expose a dependable
  // percentage for every scan profile, so 100% is reserved for a real response.
  const expectedMs = mode === "deep" ? 180000 : 18000;
  scanProgress.hidden = false;
  scanProgress.classList.remove("is-error");
  setScanProgress(3, stageMessage(3, mode));

  progressTimer = window.setInterval(() => {
    const elapsed = performance.now() - startedAt;
    const fraction = Math.min(1, elapsed / expectedMs);
    // Reach 91% near the expected duration, then wait for the server response.
    const progress = 3 + (88 * (1 - Math.pow(1 - fraction, 1.7)));
    setScanProgress(Math.min(91, progress), stageMessage(progress, mode));
  }, 260);
}

function completeScanProgress() {
  window.clearInterval(progressTimer);
  setScanProgress(100, "Scan complete — opening the new results…");
}

function failScanProgress(message) {
  window.clearInterval(progressTimer);
  if (scanProgress) scanProgress.classList.add("is-error");
  setScanProgress(0, message);
}

function setSubmittingState(form, loadingText = "Inspecting localhost") {
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (!button || button.disabled) return;
    button.disabled = true;
    button.classList.add("is-loading");
    const label = button.querySelector(".button-label");
    if (label) label.textContent = loadingText;
  });
}

document.querySelectorAll("[data-scan-form]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitter = event.submitter || form.querySelector("button[type='submit']");
    const button = submitter || form.querySelector("button[type='submit']");
    if (!button || button.disabled) return;
    const buttons = [...form.querySelectorAll("button[type='submit']")];
    const originalLabel = button.querySelector(".button-label")?.textContent;

    const mode = submitter?.value || form.querySelector("[name='scan_mode']")?.value || "quick";
    const formData = new FormData(form);
    if (submitter?.name) formData.set(submitter.name, submitter.value);

    buttons.forEach((item) => { item.disabled = true; });
    button.classList.add("is-loading");
    const label = button.querySelector(".button-label");
    if (label) label.textContent = "Scanning localhost";
    beginScanProgress(mode);

    try {
      const response = await fetch(form.action, { method: "POST", body: formData, redirect: "follow" });
      if (!response.ok) {
        window.location.assign(response.url);
        return;
      }
      completeScanProgress();
      window.setTimeout(() => window.location.assign(response.url), reduceMotion ? 0 : 360);
    } catch {
      failScanProgress("The scan request could not reach the local dashboard. Try again.");
      buttons.forEach((item) => { item.disabled = false; });
      button.classList.remove("is-loading");
      if (label && originalLabel) label.textContent = originalLabel;
    }
  });
});
document.querySelectorAll("[data-remediation-form], .auto-remediation-form").forEach((form) => {
  setSubmittingState(form, "Stopping + verifying");
});
document.querySelectorAll("[data-inspection-form]").forEach((form) => {
  setSubmittingState(form, "Inspecting owner");
});
document.querySelectorAll("[data-python-audit-form]").forEach((form) => {
  setSubmittingState(form, "Checking packages");
});

document.querySelectorAll("[data-copy-command]").forEach((button) => {
  button.addEventListener("click", async () => {
    const command = button.dataset.copyCommand;
    if (!command || !navigator.clipboard) return;
    const originalLabel = button.textContent;
    try {
      await navigator.clipboard.writeText(command);
      button.textContent = "Copied";
      window.setTimeout(() => { button.textContent = originalLabel; }, 1400);
    } catch {
      button.textContent = "Copy failed";
      window.setTimeout(() => { button.textContent = originalLabel; }, 1400);
    }
  });
});

if (!reduceMotion) {
  const intro = document.querySelectorAll("[data-intro]");
  const introCard = document.querySelectorAll("[data-intro-card]");
  if (intro.length) {
    animate(intro, { opacity: [0, 1], transform: ["translateY(18px)", "translateY(0px)"] }, { duration: 0.58, ease: [0.16, 1, 0.3, 1] });
  }
  if (introCard.length) {
    animate(introCard, { opacity: [0, 1], transform: ["translateY(14px) scale(.985)", "translateY(0px) scale(1)"] }, { duration: 0.52, delay: 0.12, ease: [0.16, 1, 0.3, 1] });
  }

  inView("[data-motion-list]", (element) => {
    animate(element.querySelectorAll("[data-motion-item]"), { opacity: [0, 1], transform: ["translateY(12px)", "translateY(0px)"] }, { duration: 0.38, delay: stagger(0.07), ease: [0.16, 1, 0.3, 1] });
  }, { amount: 0.18 });
}

window.addEventListener("load", () => {
  if (reduceMotion || !window.gsap) return;
  const { gsap } = window;
  if (window.ScrollTrigger) gsap.registerPlugin(window.ScrollTrigger);

  const revealTargets = gsap.utils.toArray("[data-reveal]");
  revealTargets.forEach((target) => {
    gsap.fromTo(target, { opacity: 0, y: 18 }, {
      opacity: 1,
      y: 0,
      duration: 0.55,
      ease: "power3.out",
      scrollTrigger: window.ScrollTrigger ? { trigger: target, start: "top 86%", once: true } : undefined,
    });
  });
});
