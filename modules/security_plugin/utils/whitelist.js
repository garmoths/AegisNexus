const WHITELIST_REFRESH_ALARM = "whitelist_refresh";
const WHITELIST_REFRESH_MINUTES = 60; // hourly
const WHITELIST_VERIFY_CACHE_KEY = "whitelist_verify_cache";
const WHITELIST_VERIFY_CACHE_TTL_MS = 60 * 60 * 1000; // 60m
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

async function getServerRequestHeaders() {
  const stored = await chrome.storage.local.get(["aegis_key"]);
  const headers = { "Content-Type": "application/json" };
  const aegisKey = String(stored.aegis_key || "").trim();
  if (aegisKey) headers["X-AegisNexus-Key"] = aegisKey;
  return headers;
}

async function getPersonalWhitelist() {
  const stored = await chrome.storage.local.get(["whitelist"]);
  return uniqueDomains(stored.whitelist);
}

async function getGlobalWhitelist() {
  const stored = await chrome.storage.local.get(["global_whitelist"]);
  return uniqueDomains(stored.global_whitelist);
}

async function readWhitelistVerifyCache() {
  const stored = await chrome.storage.local.get([WHITELIST_VERIFY_CACHE_KEY]);
  const cache = stored[WHITELIST_VERIFY_CACHE_KEY];
  return cache && typeof cache === "object" ? cache : {};
}

async function writeWhitelistVerifyCache(cache) {
  await chrome.storage.local.set({ [WHITELIST_VERIFY_CACHE_KEY]: cache });
}

async function getCachedWhitelistDecision(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return null;

  const cache = await readWhitelistVerifyCache();
  const now = Date.now();
  let dirty = false;

  for (const [key, entry] of Object.entries(cache)) {
    const checkedAt = Number(entry?.checkedAt || 0);
    if (!checkedAt || now - checkedAt > WHITELIST_VERIFY_CACHE_TTL_MS) {
      delete cache[key];
      dirty = true;
    }
  }

  if (dirty) await writeWhitelistVerifyCache(cache);

  const hit = cache[normalized];
  if (!hit || typeof hit.is_safe !== "boolean") return null;
  return hit.is_safe;
}

async function setCachedWhitelistDecision(domain, isSafe, reason = "", source = "server_verify_user") {
  const normalized = normalizeDomain(domain);
  if (!normalized) return;

  const cache = await readWhitelistVerifyCache();
  cache[normalized] = {
    is_safe: Boolean(isSafe),
    reason: String(reason || ""),
    source: String(source || "server_verify_user"),
    checkedAt: Date.now(),
  };
  await writeWhitelistVerifyCache(cache);
}

function parseVerifyUserResult(payload, domain) {
  const normalized = normalizeDomain(domain);
  const results = Array.isArray(payload?.results) ? payload.results : [];
  const match = results.find((item) => normalizeDomain(item?.domain) === normalized);
  if (match && typeof match.is_safe === "boolean") {
    return {
      found: true,
      is_safe: Boolean(match.is_safe),
      reason: String(match.reason || ""),
      source: "server_verify_user",
    };
  }

  if (payload && typeof payload.is_safe === "boolean") {
    return {
      found: true,
      is_safe: Boolean(payload.is_safe),
      reason: String(payload.reason || ""),
      source: "server_verify_user",
    };
  }

  return { found: false, is_safe: false, reason: "unknown", source: "server_verify_user" };
}

async function verifyDomainWithServer(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return { resolved: false, is_safe: false };

  const apiBaseUrl = await getApiBaseUrl();
  const headers = await getServerRequestHeaders();

  // Prefer GET for single-domain checks. Fallback to POST for backward compatibility.
  try {
    const getUrl = `${apiBaseUrl}/api/v2/whitelist/verify-user?domain=${encodeURIComponent(normalized)}`;
    const response = await fetch(getUrl, { method: "GET", headers });
    if (response.ok) {
      const payload = await response.json();
      const parsed = parseVerifyUserResult(payload, normalized);
      if (parsed.found) {
        await setCachedWhitelistDecision(normalized, parsed.is_safe, parsed.reason, parsed.source);
        return { resolved: true, is_safe: parsed.is_safe };
      }
    }
  } catch {}

  try {
    const response = await fetch(`${apiBaseUrl}/api/v2/whitelist/verify-user`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domains: [normalized] }),
    });
    if (!response.ok) return { resolved: false, is_safe: false };

    const payload = await response.json();
    const parsed = parseVerifyUserResult(payload, normalized);
    if (!parsed.found) return { resolved: false, is_safe: false };

    await setCachedWhitelistDecision(normalized, parsed.is_safe, parsed.reason, parsed.source);
    return { resolved: true, is_safe: parsed.is_safe };
  } catch {
    return { resolved: false, is_safe: false };
  }
}

async function isWhitelisted(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;

  const personal = await getPersonalWhitelist();
  if (matchesWhitelist(normalized, personal)) return true;

  const cachedDecision = await getCachedWhitelistDecision(normalized);
  if (typeof cachedDecision === "boolean") return cachedDecision;

  const serverDecision = await verifyDomainWithServer(normalized);
  if (serverDecision.resolved) return Boolean(serverDecision.is_safe);

  const global = await getGlobalWhitelist();
  const fallbackGlobalMatch = matchesWhitelist(normalized, global);
  if (fallbackGlobalMatch) {
    await setCachedWhitelistDecision(normalized, true, "global_whitelist_fallback", "local_global_whitelist");
  }
  return fallbackGlobalMatch;
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
