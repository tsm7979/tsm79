const DEFAULT_GATEWAY = "http://localhost:8080";
const dot = document.getElementById("dot");
const statusEl = document.getElementById("status");
const gwEl = document.getElementById("gw");

async function getGateway() {
  const { gateway } = await chrome.storage.sync.get({ gateway: DEFAULT_GATEWAY });
  return (gateway || DEFAULT_GATEWAY).replace(/\/+$/, "");
}

(async () => {
  const gw = await getGateway();
  gwEl.textContent = gw;

  // Liveness probe: resolve the demo name through the gateway.
  try {
    const r = await fetch(`${gw}/_tsm/resolve/hub.tsm`, { method: "GET" });
    if (r.ok) {
      dot.classList.add("up");
      statusEl.textContent = "gateway online";
    } else {
      dot.classList.add("down");
      statusEl.textContent = `gateway responded ${r.status}`;
    }
  } catch (e) {
    dot.classList.add("down");
    statusEl.textContent = "gateway unreachable";
  }

  document.getElementById("test").addEventListener("click", () => {
    chrome.tabs.create({ url: `${gw}/_tsm/hub.tsm` });
  });
  document.getElementById("opts").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
})();
