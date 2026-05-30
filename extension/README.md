# TSM Sovereign Overlay — browser extension

The front door to the ICANN-free `.tsm` namespace. It routes `.tsm` names to your
TSM data-plane **gateway** (`/_tsm/<name>`), which resolves the self-certifying
name and **governs the content through the firewall** before it loads.

## What it does

- **Omnibox keyword `tsm`** (reliable): type `tsm hub` (or `tsm hub.tsm`) in the
  address bar → the name opens through the gateway. Use this — a bare custom TLD
  typed in the address bar is otherwise treated as a web search by Chrome.
- **`.tsm` redirect** (transparent): if a navigation to `http(s)://<name>.tsm`
  fires, a `declarativeNetRequest` rule redirects it to the gateway *before it
  leaves the machine* — no DNS leak.

No name is registered with ICANN, and nothing is sent to the public DNS: a `.tsm`
name is an Ed25519 public key, resolved and served by the TSM control plane.

## Install (load unpacked)

1. Make sure your TSM gateway is reachable (the data plane's overlay endpoint).
   By default the extension targets `http://localhost:8080`. If you run the stack
   in Docker, either map the data-plane port to `8080` on the host, or set a
   different URL on the extension's **Settings** page.
2. Chrome/Edge → `chrome://extensions` → enable **Developer mode** →
   **Load unpacked** → select this `extension/` folder.
3. (Optional) Open **Settings** (extension → Details → Extension options) and set
   your **Gateway URL**.

## Use

- Address bar: `tsm hub` ↵  → opens `hub.tsm` through the governed gateway.
- Or visit `http://hub.tsm/` directly (the redirect rule catches it).
- The toolbar popup shows whether the gateway is online and a quick "open hub.tsm".

## Try the governance demo

The data plane registers two demo names at boot:

| Name | Result |
|------|--------|
| `hub.tsm`  | a clean page — **served** |
| `leak.tsm` | malicious (jailbreak) content — **blocked by the firewall (403)** |

`tsm hub` loads; `tsm leak` is blocked at the door. That's the whole point: the
overlay is a *governed* sovereign network, not a lawless one.

## Notes / limits

- Requires the TSM gateway to be reachable from the browser (it's an opt-in
  layer — like installing Tor Browser, this one-time install is the only setup).
- `https://` overlay endpoints and real P2P (libp2p DHT) resolution are upcoming
  data-plane phases; today the gateway serves built-in/`http` demo content.
