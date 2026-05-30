// Screen-record loop → viewable filmstrip.
// Launches Chromium, records timed frames of: the intro/load animation, a
// wheel-driven scroll-through (so ScrollTrigger + Lenis fire naturally), and
// the live inspect-demo interaction. Frames land in caps/ as PNGs.
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const url = process.argv[2] || "http://localhost:3000/";
mkdirSync("caps", { recursive: true });

const browser = await chromium.launch({
  headless: true,
  args: ["--use-angle=d3d11", "--ignore-gpu-blocklist", "--enable-gpu", "--enable-webgl"], // real AMD GPU
});
const page = await browser.newPage({ viewport: { width: 1440, height: 860 }, deviceScaleFactor: 1 });
page.on("pageerror", (e) => console.log("PAGEERROR:", e.message));
page.on("console", (m) => { if (m.type() === "error") console.log("CONSOLE-ERR:", m.text()); });

let n = 0;
const shot = async (label) => {
  try { await page.screenshot({ path: `caps/${String(n).padStart(2, "0")}-${label}.png`, timeout: 15000, animations: "disabled" }); console.log("frame", n, label); n++; }
  catch (e) { console.log("shot fail", label, e.message.split("\n")[0]); }
};

await page.goto(url, { waitUntil: "load" });

// ── hero (after loader reveal + WebGL freeze) ──
await page.waitForTimeout(4200); await shot("hero");         // headline revealed, GL frozen

// ── scroll-through filmstrip (wheel drives Lenis + ScrollTrigger) ──
await page.mouse.move(720, 430);
const STEPS = 30;
for (let i = 0; i < STEPS; i++) {
  await page.mouse.wheel(0, 620);
  await page.waitForTimeout(180);
  if (i % 4 === 3) await shot("scroll");
}

// ── inspect-demo interaction ──
try {
  await page.evaluate(() => document.querySelector("#inspect")?.scrollIntoView({ block: "center" }));
  await page.waitForTimeout(800);
  for (const s of ["token", "card", "clean"]) {
    const b = await page.$(`[data-sample="${s}"]`);
    if (b) { await b.click(); await page.waitForTimeout(750); await shot("inspect-" + s); }
  }
} catch (e) { console.log("inspect step fail", e.message); }

await browser.close();
console.log("DONE", n, "frames");
