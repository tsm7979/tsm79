// Targeted section capture — scrolls to specific anchors and shoots each.
// Usage: node cap-sections.mjs http://localhost:3000/ market who pricing
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const url = process.argv[2] || "http://localhost:3000/";
const ids = process.argv.slice(3);
mkdirSync("caps", { recursive: true });

const browser = await chromium.launch({
  headless: true,
  args: ["--use-angle=d3d11", "--ignore-gpu-blocklist", "--enable-gpu", "--enable-webgl"], // real AMD GPU
});
const page = await browser.newPage({ viewport: { width: 1440, height: 860 }, deviceScaleFactor: 1 });
page.on("pageerror", (e) => console.log("PAGEERROR:", e.message));
page.on("console", (m) => { if (m.type() === "error") console.log("CONSOLE-ERR:", m.text()); });

await page.goto(url, { waitUntil: "load" });
await page.waitForTimeout(3500); // let loader lift

for (const id of ids) {
  const ok = await page.evaluate((i) => {
    const el = document.getElementById(i);
    if (!el) return false;
    el.scrollIntoView({ block: "start" });
    return true;
  }, id);
  if (!ok) { console.log("missing #" + id); continue; }
  await page.waitForTimeout(1400); // reveals + bar fills
  await page.screenshot({ path: `caps/sec-${id}.png`, timeout: 15000, animations: "disabled" });
  console.log("shot #" + id);
}
await browser.close();
console.log("DONE");
