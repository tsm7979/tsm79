const DEFAULT_GATEWAY = "http://localhost:8080";
const input = document.getElementById("gateway");
const ok = document.getElementById("ok");

chrome.storage.sync.get({ gateway: DEFAULT_GATEWAY }).then(({ gateway }) => {
  input.value = gateway;
});

document.getElementById("save").addEventListener("click", async () => {
  let val = input.value.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//.test(val)) val = "http://" + val;
  await chrome.storage.sync.set({ gateway: val });
  input.value = val;
  ok.classList.add("show");
  setTimeout(() => ok.classList.remove("show"), 1500);
});
