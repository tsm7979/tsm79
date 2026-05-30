// Probe whether headless Chromium can use the real GPU (ANGLE/D3D11) vs swiftshader.
import { chromium } from "playwright";
const variants = [
  ["d3d11", ["--use-angle=d3d11", "--ignore-gpu-blocklist", "--enable-gpu"]],
  ["gl-egl", ["--use-angle=gl", "--ignore-gpu-blocklist", "--enable-gpu"]],
  ["default", ["--ignore-gpu-blocklist", "--enable-gpu"]],
  ["swiftshader", ["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"]],
];
for (const [name, args] of variants) {
  try {
    const b = await chromium.launch({ headless: true, args });
    const p = await b.newPage();
    await p.setContent("<canvas id=c></canvas>");
    const info = await p.evaluate(() => {
      const gl = document.getElementById("c").getContext("webgl2") || document.getElementById("c").getContext("webgl");
      if (!gl) return "no-webgl";
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      return dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
    });
    console.log(name.padEnd(12), "→", info);
    await b.close();
  } catch (e) { console.log(name.padEnd(12), "→ FAIL", e.message.split("\n")[0]); }
}
