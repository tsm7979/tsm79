# `landing-v4` — TSM79 sovereign landing kit

A self-contained static landing page for **TSM79 — The Sovereign Mechanica**, ported from `TSM — Sovereign Design System / ui_kits/landing/v4/`.

## What's here

| File | Role |
| --- | --- |
| `index.html` | 9 sections — hero → philosophy → architecture → policy → routing → console → CLI → trust → CTA, plus masthead, ticker, loop band, footer |
| `landing_v4.css` | All layout, components, motion, kinetic type; imports `colors_and_type.css` |
| `colors_and_type.css` | Brand tokens — colour, type scale, spacing, fonts (Google) |
| `landing_v4.js` | Loader sequence, scroll/IO reveals, console interactions, kinetic timecode, ticker logic |
| `engine_v4.js` | WebGPU/TSL hero engine — bloom, chromatic aberration, film grain, cursor-velocity flowmap, 90-frame idle guard; WebGL2 + Canvas-2D fallbacks |
| `assets/` | Brand SVGs — mark, seal, wordmark, control-plane diagram |
| `Dockerfile` | nginx-alpine static server |

## Run

### Locally (no build)

```bash
# any static server works; python is on most boxes
cd landing-v4
python -m http.server 8765
# visit http://localhost:8765
```

### Docker

```bash
docker build -t tsm-landing-v4 .
docker run --rm -p 8080:80 tsm-landing-v4
# visit http://localhost:8080
```

## Engine pipeline (engine_v4.js)

Implements the shader.se-class hero pipeline the brief calls for:

- `THREE.WebGPURenderer` initialised async; auto-falls-back to WebGL2 if WebGPU isn't available
- TSL node post-processing graph: scene `pass` → `bloom` → directional chromatic aberration → film grain → screen
- Cursor-velocity **flowmap** drives the aberration direction and intensity
- 90-frame **idle guard** suspends the render loop after inactivity, resumes on input
- If WebGPU/TSL fail to load entirely, a vanilla canvas-2D fallback runs — the page is never blank

**Not** in v4 (deliberate scope choice): reverse-order FBO chaining, per-section selective render passes, `@pmndrs/uikit` canvas-bound UI. v4 has one canvas (the hero) and renders the other 8 sections as styled HTML/SVG — lighter, more accessible, more mobile-friendly than a fully-3D page.

## Brand rules (excerpt)

- Square corners, hairline borders, no drop shadows
- Exactly one `#C7F23E` (`--signal`) element per fold — the lamp
- Mask-wipe reveals only — never opacity-only
- House glyph: em-dash `—`. Permitted dingbats: `◇ ◆ ▲ ● ─ │ ┼`. No emoji.
- Banned words: empower / unlock / seamless / leverage / revolutionary / AI-powered
- The landing **never ends** — the bottom seamlessly loops to the top with the timecode incrementing

See the full brand source: `Downloads/TSM — Sovereign Design System/README.md`.

## Fonts

- Display: `Editorial New` (PP Editorial New) — **not bundled**. Fallback chain is `Newsreader` (Google Fonts, loaded), then `Times New Roman`, then `serif`. If/when you license PP Editorial New, drop the woff2 files in `./fonts/` and uncomment the `@font-face` block at the top of `colors_and_type.css`.
- Sans: `Inter Tight` — Google Fonts
- Mono: `JetBrains Mono` — Google Fonts

## Notes

- This is parallel to, not a replacement for, the existing Vite project at `TSMv1/landing/`. Both coexist. When you're ready to retire the Vite project, point your tunnel/CDN at this folder instead.
- The CDN imports (Lenis @1.1.18, three @0.178.0) are pinned — bump them in `index.html` when you want updates.
