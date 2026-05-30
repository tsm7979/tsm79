/* ============================================================================
   Pinned 3-phase scrollytelling: Firewall → Governance → Sovereign Stack.
   Type-led with a bold ghosted phase numeral (01/02/03). No weak 2D canvas.
   ========================================================================== */
import { ScrollTrigger } from "gsap/ScrollTrigger";

export function initPhases() {
  const section = document.querySelector<HTMLElement>("[data-phases]");
  if (!section) return;
  const steps = [...section.querySelectorAll<HTMLElement>(".phase-step")];
  const bars = [...section.querySelectorAll<HTMLElement>("[data-bar]")];
  const fig = section.querySelector<HTMLElement>("[data-phase-fig]");
  const figs = ["01", "02", "03"];
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  let mode = -1;
  const setMode = (m: number) => {
    if (m === mode) return;
    mode = m;
    steps.forEach((s, i) => s.classList.toggle("active", i === m));
    if (fig) {
      fig.textContent = figs[m] ?? "01";
      fig.style.opacity = "0"; fig.style.transform = "translateY(14px)";
      requestAnimationFrame(() => { fig.style.opacity = "1"; fig.style.transform = "none"; });
    }
  };
  setMode(0);

  if (!reduced) {
    ScrollTrigger.create({
      trigger: section, start: "top top", end: "+=300%", pin: ".phases-pin", scrub: true,
      onUpdate(self) {
        const p = self.progress;
        setMode(p < 0.34 ? 0 : p < 0.67 ? 1 : 2);
        bars.forEach((b, i) => { b.style.width = `${Math.min(1, Math.max(0, p * 3 - i)) * 100}%`; });
      },
    });
  } else {
    steps.forEach((s) => s.classList.add("active"));
  }
}
