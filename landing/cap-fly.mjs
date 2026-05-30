// Capture the pinned hero dive at several scroll depths.
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
const url = process.argv[2] || "http://localhost:3000/";
mkdirSync("caps", { recursive: true });
const b = await chromium.launch({ headless: true, args: ["--use-angle=d3d11", "--ignore-gpu-blocklist", "--enable-gpu"] });
const p = await b.newPage({ viewport: { width: 1440, height: 860 }, deviceScaleFactor: 1 });
p.on("pageerror", (e) => console.log("PAGEERROR:", e.message));
await p.goto(url, { waitUntil: "load" });
await p.waitForTimeout(3600); // loader lifts
for (const y of [200, 1000, 1700, 2400, 3100, 3700]) {
  await p.mouse.wheel(0, y - (await p.evaluate(() => window.scrollY)));
  await p.waitForTimeout(900);
  await p.screenshot({ path: `caps/fly-${y}.png`, timeout: 15000 });
  console.log("shot", y);
}
await b.close(); console.log("DONE");
