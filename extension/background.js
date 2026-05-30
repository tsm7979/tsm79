// TSM Sovereign Overlay — MV3 background service worker.
//
// Two entry points into the ICANN-free `.tsm` namespace:
//   1. Omnibox keyword `tsm`  → type `tsm hub` (or `tsm hub.tsm`) and we open the
//      name through the gateway. This is the RELIABLE path: a bare custom-TLD
//      typed in the address bar is otherwise treated as a search by Chrome.
//   2. declarativeNetRequest redirect → if a navigation to `http(s)://<name>.tsm`
//      does fire, we transparently redirect it to the gateway before it leaves
//      the machine (no DNS leak).
//
// The gateway is your TSM data plane's overlay endpoint (`/_tsm/<name>`), which
// resolves the self-certifying name AND governs the content through the firewall.
// It is configurable on the options page (default: http://localhost:8080).

const DEFAULT_GATEWAY = "http://localhost:8080";
const RULE_ID = 1;

async function getGateway() {
  const { gateway } = await chrome.storage.sync.get({ gateway: DEFAULT_GATEWAY });
  return (gateway || DEFAULT_GATEWAY).replace(/\/+$/, "");
}

function gatewayUrlForName(gw, rawName) {
  let name = rawName.trim().replace(/^\/+/, "");
  if (name.length && !name.includes(".")) name += ".tsm"; // "hub" → "hub.tsm"
  return `${gw}/_tsm/${encodeURIComponent(name)}`;
}

// Install/refresh the `<name>.tsm` → gateway redirect rule (dynamic so it can
// track the configured gateway). Capture group \1 = the .tsm host.
async function installRedirectRule() {
  const gw = await getGateway();
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [RULE_ID],
      addRules: [
        {
          id: RULE_ID,
          priority: 1,
          action: {
            type: "redirect",
            redirect: { regexSubstitution: `${gw}/_tsm/\\1` }
          },
          condition: {
            // Match http(s)://<host>.tsm[:port][/path] and capture the host.
            regexFilter: "^https?://([^/:]+\\.tsm)(?::\\d+)?(?:/.*)?$",
            resourceTypes: ["main_frame"]
          }
        }
      ]
    });
  } catch (e) {
    console.error("[tsm] failed to install redirect rule:", e);
  }
}

chrome.runtime.onInstalled.addListener(installRedirectRule);
chrome.runtime.onStartup.addListener(installRedirectRule);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "sync" && changes.gateway) installRedirectRule();
});

// Omnibox suggestion + entry.
chrome.omnibox.setDefaultSuggestion({
  description: "Open <match>%s</match> in the TSM sovereign overlay (.tsm)"
});

chrome.omnibox.onInputEntered.addListener(async (text, disposition) => {
  const gw = await getGateway();
  const url = gatewayUrlForName(gw, text);
  if (disposition === "newForegroundTab") {
    chrome.tabs.create({ url });
  } else if (disposition === "newBackgroundTab") {
    chrome.tabs.create({ url, active: false });
  } else {
    chrome.tabs.update({ url });
  }
});
