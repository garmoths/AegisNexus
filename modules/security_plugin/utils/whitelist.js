const WHITELIST_REFRESH_ALARM = "whitelist_refresh";
const WHITELIST_REFRESH_MINUTES = 43200; // monthly
const API_BASE_URL_DEFAULT = "http://127.0.0.1:8000";

let alarmListenerBound = false;

function normalizeDomain(domain) {
  return String(domain || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

function uniqueDomains(domains) {
  return [...new Set((Array.isArray(domains) ? domains : []).map(normalizeDomain).filter(Boolean))];
}

function matchesWhitelist(domain, whitelist) {
  const d = normalizeDomain(domain);
  if (!d) return false;
  return whitelist.some((entry) => d === entry || d.endsWith(`.${entry}`));
}

async function getApiBaseUrl() {
  const stored = await chrome.storage.local.get(["api_base_url"]);
  const configured = String(stored.api_base_url || "").trim();
  return (configured || API_BASE_URL_DEFAULT).replace(/\/+$/g, "");
}

async function getPersonalWhitelist() {
  const stored = await chrome.storage.local.get(["whitelist"]);
  return uniqueDomains(stored.whitelist);
}

async function getGlobalWhitelist() {
  const stored = await chrome.storage.local.get(["global_whitelist"]);
  return uniqueDomains(stored.global_whitelist);
}

async function isWhitelisted(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;

  const personal = await getPersonalWhitelist();
  if (matchesWhitelist(normalized, personal)) return true;

  const global = await getGlobalWhitelist();
  return matchesWhitelist(normalized, global);
}

async function addToPersonalWhitelist(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;

  const current = await getPersonalWhitelist();
  if (current.includes(normalized)) return false;

  const next = [...current, normalized];
  await chrome.storage.local.set({ whitelist: next });
  return true;
}

async function removeFromPersonalWhitelist(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;

  const current = await getPersonalWhitelist();
  const next = current.filter((item) => item !== normalized);
  if (next.length === current.length) return false;

  await chrome.storage.local.set({ whitelist: next });
  return true;
}

async function notifyWhitelistWarning(domain) {
  await chrome.notifications.create({
    type: "basic",
    iconUrl:
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAukB9Wyp7mQAAAAASUVORK5CYII=",
    title: "AegisNexus Shield",
    message: `⚠️ "${domain}" artık güvenli değil, whitelist'inden çıkarıldı`,
    priority: 2,
  });
}

async function notifyWhitelistInfo(domain) {
  await chrome.notifications.create({
    type: "basic",
    iconUrl:
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAukB9Wyp7mQAAAAASUVORK5CYII=",
    title: "AegisNexus Shield",
    message: `ℹ️ "${domain}" global whitelist'te bulunamadı, kişisel listenizde kalmaya devam ediyor`,
    priority: 1,
  });
}

async function verifyPersonalWhitelist() {
  const personal = await getPersonalWhitelist();
  if (personal.length === 0) return true;

  const apiBaseUrl = await getApiBaseUrl();
  let response;
  try {
    response = await fetch(`${apiBaseUrl}/api/v2/whitelist/verify-user`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains: personal }),
    });
  } catch {
    return false;
  }

  if (!response.ok) return false;

  let payload;
  try {
    payload = await response.json();
  } catch {
    return false;
  }

  const results = Array.isArray(payload?.results) ? payload.results : [];
  const domainsToRemove = new Set();

  for (const item of results) {
    const domain = normalizeDomain(item?.domain);
    if (!domain || item?.is_safe === true) continue;

    if (String(item?.reason || "") === "not_in_whitelist") {
      await notifyWhitelistInfo(domain);
      continue;
    }

    domainsToRemove.add(domain);
    await notifyWhitelistWarning(domain);
  }

  if (domainsToRemove.size === 0) return true;

  const next = personal.filter((domain) => !domainsToRemove.has(domain));
  await chrome.storage.local.set({ whitelist: next });
  return true;
}

async function refreshGlobalWhitelist() {
  const apiBaseUrl = await getApiBaseUrl();
  const response = await fetch(`${apiBaseUrl}/api/v2/whitelist/global`, { method: "GET" });
  if (!response.ok) return false;

  const text = await response.text();
  const list = uniqueDomains(text.split("\n"));
  if (list.length === 0) return false;

  await chrome.storage.local.set({ global_whitelist: list });
  await verifyPersonalWhitelist();
  return true;
}

function bindWhitelistAlarmListener() {
  if (alarmListenerBound) return;
  alarmListenerBound = true;

  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name !== WHITELIST_REFRESH_ALARM) return;
    refreshGlobalWhitelist().catch((error) => {
      console.warn("AegisNexus Shield: whitelist refresh failed", error);
    });
  });
}

async function initializeWhitelistRefresh() {
  bindWhitelistAlarmListener();
  await chrome.alarms.create(WHITELIST_REFRESH_ALARM, { periodInMinutes: WHITELIST_REFRESH_MINUTES });
}

export {
  isWhitelisted,
  getPersonalWhitelist,
  addToPersonalWhitelist,
  removeFromPersonalWhitelist,
  getGlobalWhitelist,
  initializeWhitelistRefresh,
};
