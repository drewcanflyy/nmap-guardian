/* Motion is the modern evolution of Framer Motion. GSAP handles page-level choreography. */
import { animate, inView, stagger } from "https://cdn.jsdelivr.net/npm/motion@14.8.0/+esm";

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function setSubmittingState(form) {
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (!button || button.disabled) return;
    button.disabled = true;
    button.classList.add("is-loading");
    const label = button.querySelector(".button-label");
    if (label) label.textContent = "Inspecting localhost";
  });
}

document.querySelectorAll("form[action$='/scan']").forEach(setSubmittingState);

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
