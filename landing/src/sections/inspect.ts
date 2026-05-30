/* ============================================================================
   Signature interaction — "Inspect a prompt, live."
   Type (or inject) a prompt; TSM scans it client-side (the same detection
   classes the real engine uses), highlights PII/secrets, decides a verdict
   (ALLOW / REDACT / BLOCK), shows the redacted output + latency. This is the
   product, demonstrated in the browser.
   ========================================================================== */
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

type Sev = "critical" | "high" | "medium";
interface Rule { type: string; sev: Sev; re: RegExp; }

// In-browser highlight rules — deliberately a touch more permissive than the
// dataplane's production regex set so demo fixtures that include `_`/`-` to
// avoid tripping public secret scanners (GitHub Push Protection, etc.) still
// render with a [REDACTED] mark in the visual. The real engine in Rust enforces
// the strict patterns.
const RULES: Rule[] = [
  { type: "GITHUB_TOKEN", sev: "critical", re: /\bghp_[A-Za-z0-9_-]{20,}\b/g },
  { type: "OPENAI_KEY",   sev: "critical", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/g },
  { type: "ANTHROPIC_KEY",sev: "critical", re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g },
  { type: "AWS_KEY",      sev: "critical", re: /\bAKIA[0-9A-Z_]{16,}\b/g },
  { type: "PRIVATE_KEY",  sev: "critical", re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { type: "JWT",          sev: "high",     re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { type: "SSN",          sev: "high",     re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: "CREDIT_CARD",  sev: "high",     re: /\b(?:\d[ -]?){13,16}\b/g },
  { type: "EMAIL",        sev: "medium",   re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "PHONE",        sev: "medium",   re: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },
];

const SAMPLES: Record<string, string> = {
  ssn: "Hi, my SSN is 123-45-6789 and I need help filing my 2025 taxes.",
  token: "Deploy with this: GITHUB_TOKEN=ghp_DEMO_FIXTURE_NOT_A_REAL_TOKEN_ab12cd",
  aws: "Use creds AKIA_DEMO_FIXTURE_AB for the S3 bucket, ping me at ops@acme.io",
  card: "Charge card 4111 1111 1111 1111, contact 415-555-0132 for receipts.",
  clean: "Summarise the Q3 board deck into five concise bullet points.",
};

interface Finding { type: string; sev: Sev; start: number; end: number; }

function scan(text: string): Finding[] {
  const out: Finding[] = [];
  for (const r of RULES) {
    r.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = r.re.exec(text))) {
      // crude overlap guard: skip if inside an existing finding
      if (!out.some((f) => m!.index < f.end && m!.index + m![0].length > f.start)) {
        out.push({ type: r.type, sev: r.sev, start: m.index, end: m.index + m[0].length });
      }
      if (m[0].length === 0) r.re.lastIndex++;
    }
  }
  return out.sort((a, b) => a.start - b.start);
}

const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));

function highlight(text: string, finds: Finding[]): string {
  if (!finds.length) return esc(text);
  let html = "", i = 0;
  for (const f of finds) {
    html += esc(text.slice(i, f.start));
    const cls = f.sev === "critical" ? "block" : f.sev === "high" ? "redact" : "warnpii";
    html += `<mark class="${cls}">${esc(text.slice(f.start, f.end))}</mark>`;
    i = f.end;
  }
  html += esc(text.slice(i));
  return html;
}

function redactText(text: string, finds: Finding[]): string {
  let out = "", i = 0;
  for (const f of finds) {
    out += esc(text.slice(i, f.start));
    out += `<b class="rd">[REDACTED:${f.type}]</b>`;
    i = f.end;
  }
  out += esc(text.slice(i));
  return out;
}

export function initInspect() {
  const root = document.querySelector<HTMLElement>("[data-inspect]");
  if (!root) return;
  const input = root.querySelector<HTMLTextAreaElement>("[data-inspect-input]")!;
  const hl = root.querySelector<HTMLElement>("[data-inspect-hl]")!;
  const verdict = root.querySelector<HTMLElement>("[data-inspect-verdict]")!;
  const chips = root.querySelector<HTMLElement>("[data-inspect-chips]")!;
  const outEl = root.querySelector<HTMLElement>("[data-inspect-out]")!;
  const route = root.querySelector<HTMLElement>("[data-inspect-route]")!;
  const lat = root.querySelector<HTMLElement>("[data-inspect-latency]")!;

  function render() {
    const text = input.value;
    const finds = scan(text);
    hl.innerHTML = highlight(text, finds) || "&nbsp;";

    const hasSecret = finds.some((f) => f.sev === "critical");
    const hasPII = finds.some((f) => f.sev !== "critical");
    const v = hasSecret ? "BLOCK" : hasPII ? "REDACT" : "ALLOW";
    verdict.dataset.v = v;
    verdict.textContent = v;

    const uniq = [...new Set(finds.map((f) => f.type))];
    chips.innerHTML = uniq.length
      ? uniq.map((t) => {
          const sev = finds.find((f) => f.type === t)!.sev;
          const c = sev === "critical" ? "block" : sev === "high" ? "redact" : "warnpii";
          return `<span class="ichip ${c}">${t.replace(/_/g, " ")}</span>`;
        }).join("")
      : `<span class="ichip ok">no sensitive data</span>`;

    outEl.innerHTML = finds.length ? redactText(text, finds) : esc(text || "—");
    route.textContent = hasSecret
      ? "blocked — secret never left your machine"
      : hasPII
      ? "routed to local model — cloud never saw the original"
      : "forwarded unchanged → upstream model";
    route.dataset.v = v;
    lat.textContent = (8 + Math.round(finds.length * 1.6 + Math.random() * 6)) + "ms";

    gsap.fromTo(chips.children, { y: 8, opacity: 0 }, { y: 0, opacity: 1, stagger: 0.05, duration: 0.4, ease: "power2.out" });
    gsap.fromTo(verdict, { scale: 0.9 }, { scale: 1, duration: 0.35, ease: "back.out(2)" });
  }

  let t: number | undefined;
  input.addEventListener("input", () => { clearTimeout(t); t = window.setTimeout(render, 120); });

  root.querySelectorAll<HTMLElement>("[data-sample]").forEach((b) => {
    b.addEventListener("click", () => {
      input.value = SAMPLES[b.dataset.sample!] || "";
      root.querySelectorAll("[data-sample]").forEach((x) => x.classList.remove("on"));
      b.classList.add("on");
      render();
    });
  });

  input.value = SAMPLES.ssn;
  ScrollTrigger.create({ trigger: root, start: "top 75%", once: true, onEnter: render });
  render();
}
