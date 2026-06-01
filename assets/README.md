# Brand assets

Committed SVG so they render on GitHub with no build step, no CI, no external tooling.

| File | Purpose | Size |
|---|---|---|
| `hero.svg` | README header banner | 1280 × 440 |
| `architecture.svg` | Request-path diagram (under **The Stack**) | 1280 × 720 |
| `social-preview.svg` | Repo social card (link unfurls on Slack / X / LinkedIn) | 1280 × 640 |

## Visual grammar

The TSM look is deliberate and consistent across every surface:

- **Canvas** — near-black `#0A0B0D`
- **Signal accent** — a single lime `#C7F23E`, used sparingly (one accent per fold)
- **Text** — off-white `#ECEEEA`, muted `#8A8F98`, dim `#5B6068`
- **Corners** — square. No rounded radii.
- **Borders** — hairline (`1px`, `#23262C`). No drop shadows. No gradients.
- **Type** — bold grotesque wordmark; monospace for labels and the verdict rail.
- **Motif** — instrument-panel frame with corner registration ticks.

## Setting the GitHub social preview

GitHub's social-preview slot takes a raster image, not SVG, and must be set in the UI:

1. Render `social-preview.svg` to PNG at 1280 × 640 (any SVG → PNG export; e.g. open in a browser and screenshot, or `rsvg-convert -w 1280 -h 640 social-preview.svg -o social-preview.png`).
2. Repo **Settings → General → Social preview → Upload an image**.

This is the one asset that can't be wired purely from the repo — it's a one-click manual upload.
