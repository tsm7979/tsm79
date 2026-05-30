import "@fontsource-variable/fraunces/index.css";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/space-mono/400.css";
import "./styles/main.scss";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Lenis from "lenis";
import { initPhases } from "./sections/phases";
import { initInspect } from "./sections/inspect";
import { initHero } from "./webgl/hero";

gsap.registerPlugin(ScrollTrigger);
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const coarse = matchMedia("(pointer: coarse)").matches;
const $ = <T extends Element = HTMLElement>(s: string) => document.querySelector<T>(s);

/* ── Smooth scroll ── */
const lenis = new Lenis({ smoothWheel: true, lerp: 0.1 });
lenis.on("scroll", ScrollTrigger.update);
gsap.ticker.add((t) => lenis.raf(t * 1000));
gsap.ticker.lagSmoothing(0);

document.querySelectorAll<HTMLAnchorElement>('a[href^="#"]').forEach((a) => {
  a.addEventListener("click", (e) => {
    const id = a.getAttribute("href")!;
    if (id.length < 2) return;
    const el = document.querySelector(id);
    if (el) { e.preventDefault(); lenis.scrollTo(el as HTMLElement, { duration: 1.4 }); }
  });
});

/* ── Custom cursor ── */
if (!coarse) {
  const ring = $(".cursor")!, dot = $(".cursor-dot")!;
  const rx = gsap.quickTo(ring, "x", { duration: 0.5, ease: "power3" });
  const ry = gsap.quickTo(ring, "y", { duration: 0.5, ease: "power3" });
  addEventListener("mousemove", (e) => {
    rx(e.clientX); ry(e.clientY);
    dot.style.transform = `translate(${e.clientX}px, ${e.clientY}px) translate(-50%,-50%)`;
  });
  document.querySelectorAll("a, button, .cell, [data-copy]").forEach((el) => {
    el.addEventListener("mouseenter", () => ring.classList.add("is-hover"));
    el.addEventListener("mouseleave", () => ring.classList.remove("is-hover"));
  });
  /* magnetic buttons */
  document.querySelectorAll<HTMLElement>(".btn").forEach((btn) => {
    btn.addEventListener("mousemove", (e) => {
      const r = btn.getBoundingClientRect();
      gsap.to(btn, { x: (e.clientX - (r.left + r.width / 2)) * 0.4, y: (e.clientY - (r.top + r.height / 2)) * 0.5, duration: 0.4, ease: "power3" });
    });
    btn.addEventListener("mouseleave", () => gsap.to(btn, { x: 0, y: 0, duration: 0.7, ease: "elastic.out(1,0.4)" }));
  });
}

/* ── Boot scrollytelling + signature demo ── */
initPhases();
initInspect();

/* ── Hero 3D: the Sovereign Core. Visible over the hero AND the CTA finale
   (page opens & closes on the centerpiece); dimmed for the data sections. ── */
const webgl = $<HTMLCanvasElement>("canvas.webgl");
if (webgl) {
  initHero(webgl, () => webgl.classList.add("is-live"));
  let heroVis = true, ctaVis = false;
  const syncCore = () => webgl.classList.toggle("is-dim", !(heroVis || ctaVis));
  ScrollTrigger.create({ trigger: "#hero", start: "top top", end: "bottom bottom", onToggle: (s) => { heroVis = s.isActive; syncCore(); } });
  ScrollTrigger.create({ trigger: "#deploy", start: "top 70%", end: "bottom top", onToggle: (s) => { ctaVis = s.isActive; syncCore(); } });
}

/* ── Hero reel: pinned centre cycler — scroll cycles the words in place ── */
const reelEl = $<HTMLElement>("#hero.reel");
if (reelEl && !reduced) {
  const sts = [...reelEl.querySelectorAll<HTMLElement>(".reel-st")];
  const bot = reelEl.querySelector<HTMLElement>("[data-reel-bot]");
  const bar = reelEl.querySelector<HTMLElement>("[data-reel-bar]");
  const caps = [
    "The AI Firewall · zero code changes",
    "Scans for PII, secrets & jailbreaks",
    "Deterministic masking, in real time",
    "Cloud or local — chosen by policy",
    "Merkle-chained, tamper-evident audit",
    "BYOK · on-prem · air-gapped",
  ];
  const n = sts.length;
  let curSt = 0;
  ScrollTrigger.create({
    trigger: "#hero", start: "top top", end: "bottom bottom", scrub: 0.4,
    onUpdate(self) {
      const p = self.progress;
      if (bar) bar.style.width = `${p * 100}%`;
      const i = Math.min(n - 1, Math.round(p * (n - 1)));
      if (i !== curSt) {
        curSt = i;
        sts.forEach((s, k) => s.classList.toggle("is-active", k === i));
        if (bot) bot.textContent = caps[i] ?? "";
      }
    },
  });
}

/* ── Hero reveal (gated behind loader) ── */
function revealHero() {
  // .reel-pin is pre-set hidden by the loader; fade the centre reel in once.
  if (reduced) { gsap.set(".reel-pin", { autoAlpha: 1, y: 0 }); return; }
  gsap.to(".reel-pin", { autoAlpha: 1, y: 0, duration: 1.1, ease: "power3.out" });
}

/* ── Cinematic loader ── */
const loader = $("[data-loader]");
const loadNum = $("[data-load]");
const loadBar = $("[data-load-bar]");
if (loader && !reduced) {
  gsap.set(".reel-pin", { autoAlpha: 0, y: 24 });
  const o = { v: 0 };
  gsap.to(o, {
    v: 100, duration: 2.1, ease: "power2.inOut",
    onUpdate() {
      const v = Math.round(o.v);
      if (loadNum) loadNum.textContent = String(v).padStart(2, "0");
      if (loadBar) loadBar.style.width = `${v}%`;
    },
    onComplete() {
      loader.classList.add("is-done");
      setTimeout(revealHero, 380);
    },
  });
} else {
  loader?.classList.add("is-done");
  revealHero();
}

/* ── Generic reveals (skip hero + headings — both handled separately) ── */
document.querySelectorAll<HTMLElement>(".reveal").forEach((el) => {
  if (el.closest(".hero") || el.matches("h1, h2")) return;
  gsap.from(el, {
    opacity: 0, y: 44, duration: 0.95, ease: "power3.out",
    scrollTrigger: { trigger: el, start: "top 88%" },
  });
});

/* ── Cinematic heading reveals — clip-wipe + rise (editorial) ── */
if (!reduced) {
  document.querySelectorAll<HTMLElement>("h2").forEach((h) => {
    if (h.closest(".hero") || h.closest(".phases")) return;   // hero=loader, phases=pinned
    gsap.set(h, { willChange: "clip-path, transform" });
    gsap.from(h, {
      yPercent: 16, autoAlpha: 0, clipPath: "inset(0 0 110% 0)",
      duration: 1.15, ease: "power4.out",
      scrollTrigger: { trigger: h, start: "top 86%" },
      onComplete: () => gsap.set(h, { clearProps: "willChange,clipPath" }),
    });
  });
}

/* ── Kinetic sentence ── */
const kin = $("[data-kinetic]");
if (kin) {
  const frag = document.createDocumentFragment();
  kin.childNodes.forEach((node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      (node.textContent || "").split(/(\s+)/).forEach((tok) => {
        if (tok.trim()) { const s = document.createElement("span"); s.className = "w"; s.textContent = tok; frag.appendChild(s); }
        else frag.appendChild(document.createTextNode(tok));
      });
    } else frag.appendChild(node.cloneNode(true));
  });
  kin.innerHTML = ""; kin.appendChild(frag);
  if (!reduced) {
    gsap.from(kin.querySelectorAll(".w"), {
      opacity: 0.1, duration: 0.6, ease: "none", stagger: 0.025,
      scrollTrigger: { trigger: kin, start: "top 80%", end: "bottom 62%", scrub: true },
    });
    gsap.from(kin.querySelectorAll(".chip"), {
      scale: 0.5, opacity: 0, transformOrigin: "center", ease: "back.out(2)", stagger: 0.12,
      scrollTrigger: { trigger: kin, start: "top 70%" },
    });
  }
}

/* ── Problem statement scrub reveal ── */
const prob = $("[data-problem]");
if (prob) {
  const words = (prob.textContent || "").trim().split(/\s+/);
  prob.innerHTML = words.map((w) => `<span class="w">${w}</span>`).join(" ");
  if (!reduced) {
    gsap.from(prob.querySelectorAll(".w"), {
      opacity: 0.12, duration: 0.6, ease: "none", stagger: 0.02,
      scrollTrigger: { trigger: prob, start: "top 78%", end: "bottom 60%", scrub: true },
    });
  }
}

/* ── Marquee ── */
const track = $("[data-marquee]");
if (track && !reduced) gsap.to(track, { xPercent: -50, duration: 26, ease: "none", repeat: -1 });

/* ── Stats count-up ── */
document.querySelectorAll<HTMLElement>("[data-count]").forEach((el) => {
  const target = parseFloat(el.dataset.count || "0");
  const dec = parseInt(el.dataset.dec || "0");
  ScrollTrigger.create({
    trigger: el, start: "top 90%", once: true,
    onEnter() {
      const o = { v: 0 };
      gsap.to(o, { v: target, duration: 1.8, ease: "power2.out", onUpdate() { el.textContent = o.v.toFixed(dec); } });
    },
  });
});

/* ── Market scale bars (fill on scroll via CSS transition) ── */
document.querySelectorAll<HTMLElement>("[data-bar-w]").forEach((el) => {
  const w = el.dataset.barW || "0";
  ScrollTrigger.create({
    trigger: el, start: "top 92%", once: true,
    onEnter() { el.style.width = `${w}%`; },
  });
});

/* ── Bento cursor glow ── */
document.querySelectorAll<HTMLElement>(".cell").forEach((cell) => {
  cell.addEventListener("mousemove", (e) => {
    const r = cell.getBoundingClientRect();
    cell.style.setProperty("--mx", `${((e.clientX - r.left) / r.width) * 100}%`);
    cell.style.setProperty("--my", `${((e.clientY - r.top) / r.height) * 100}%`);
  });
});

/* ── Card 3D tilt (cursor-tracked; signature micro-interaction) ── */
if (!coarse && !reduced) {
  document.querySelectorAll<HTMLElement>(".cell, .who-card, .price").forEach((card) => {
    gsap.set(card, { transformPerspective: 800 });
    const rx = gsap.quickTo(card, "rotationX", { duration: 0.6, ease: "power3" });
    const ry = gsap.quickTo(card, "rotationY", { duration: 0.6, ease: "power3" });
    const sc = gsap.quickTo(card, "scale", { duration: 0.6, ease: "power3" });
    card.addEventListener("mousemove", (e) => {
      const r = card.getBoundingClientRect();
      rx(-((e.clientY - r.top) / r.height - 0.5) * 7);
      ry(((e.clientX - r.left) / r.width - 0.5) * 9);
      sc(1.025);
      card.style.setProperty("--mx", `${((e.clientX - r.left) / r.width) * 100}%`);
      card.style.setProperty("--my", `${((e.clientY - r.top) / r.height) * 100}%`);
    });
    card.addEventListener("mouseleave", () => { rx(0); ry(0); sc(1); });
  });
}

/* ── Copy command ── */
const copy = $("[data-copy]");
copy?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText("pip install tsm-firewall && tsm enable");
    const prev = copy.textContent; copy.textContent = "copied ✓";
    setTimeout(() => (copy.textContent = prev), 1600);
  } catch { /* clipboard blocked */ }
});

/* ── Nav retract (hide on scroll down, reveal on scroll up) ── */
{
  let lastY = 0;
  lenis.on("scroll", () => {
    const nav = $(".nav"); if (!nav) return;
    const y = scrollY;
    if (y < 120) nav.classList.remove("nav--hidden");
    else if (Math.abs(y - lastY) > 6) nav.classList.toggle("nav--hidden", y > lastY);
    lastY = y;
  });
}

/* ── Nav background after scroll ── */
ScrollTrigger.create({
  start: "top top", end: "max",
  onUpdate() {
    const nav = $(".nav")!; const on = scrollY > 80;
    nav.style.background = on ? "rgba(6,8,10,0.6)" : "transparent";
    nav.style.backdropFilter = on ? "blur(12px)" : "none";
    (nav.style as any).webkitBackdropFilter = on ? "blur(12px)" : "none";
  },
});

addEventListener("load", () => ScrollTrigger.refresh());
