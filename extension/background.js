const pending = new Map();
const errors = new Set([
  "net::ERR_CONNECTION_RESET", "net::ERR_CONNECTION_TIMED_OUT", "net::ERR_CONNECTION_CLOSED",
  "net::ERR_CONNECTION_REFUSED", "net::ERR_TIMED_OUT", "net::ERR_TUNNEL_CONNECTION_FAILED",
  "net::ERR_SSL_PROTOCOL_ERROR", "net::ERR_NAME_NOT_RESOLVED"
]);

async function call(path, body, settings) {
  settings ||= await chrome.storage.local.get(["token", "port"]);
  if (!settings.token) return null;
  const response = await fetch(`http://127.0.0.1:${settings.port || 47831}${path}`, {
    method: body ? "POST" : "GET",
    headers: {Authorization: `Bearer ${settings.token}`, "Content-Type": "application/json"},
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
    signal: AbortSignal.timeout(35000)
  });
  if (!response.ok) throw new Error(`Pathfinder HTTP ${response.status}`);
  return response.json();
}

async function refresh() {
  try {
    const state = await call("/status");
    if (state) await chrome.storage.session.set({network: state.network, networkAt: Date.now()});
  } catch (_) { /* Engine may be stopped; never change browser settings here. */ }
}

chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"});
  chrome.alarms.create("network", {periodInMinutes: 0.5});
  refresh();
});
chrome.runtime.onStartup.addListener(refresh);
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === "network") refresh(); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.token || changes.port)) refresh();
});

chrome.webRequest.onBeforeRequest.addListener(details => {
  if (details.type !== "main_frame" || !["GET", "HEAD"].includes(details.method)) return;
  if (pending.size >= 256) pending.delete(pending.keys().next().value);
  const started = details.timeStamp / 1000;
  pending.set(details.requestId, chrome.storage.session.get(["network", "networkAt"]).then(state => {
    if (!state.network || Date.now() - state.networkAt > 60000) return null;
    return {host: new URL(details.url).hostname, network: state.network, started};
  }));
}, {urls: ["https://*/*"], types: ["main_frame"]});

async function report(details, outcome) {
  const entry = pending.get(details.requestId);
  pending.delete(details.requestId);
  if (!entry || details.fromCache) return;
  try {
    const event = await entry;
    if (event && outcome) await call("/event", {...event, outcome, status: details.statusCode || null});
  } catch (_) { /* No remote logging and no automatic page/form replay. */ }
}

chrome.webRequest.onCompleted.addListener(details => {
  report(details, details.statusCode >= 200 && details.statusCode < 400 ? "success" : "http_inconclusive");
}, {urls: ["https://*/*"], types: ["main_frame"]});
chrome.webRequest.onErrorOccurred.addListener(details => {
  report(details, errors.has(details.error) ? "transport_error" : null);
}, {urls: ["https://*/*"], types: ["main_frame"]});
