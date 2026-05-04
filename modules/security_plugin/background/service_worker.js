self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));

import { BloomFilter } from "../utils/bloom_filter.js";
import { addToPersonalWhitelist, removeFromPersonalWhitelist, initializeWhitelistRefresh, isWhitelisted } from "../utils/whitelist.js";
import { analyzeURL } from "../utils/heuristic.js";
import { checkDomainViaDNS } from "../utils/dns_check.js";
import { checkURL as checkGoogleSafeBrowsing } from "../utils/gsb_check.js";

const DOMAIN_CACHE_KEY = "domain_cache";
const DOMAIN_CACHE_TTL_MS = 86400000; // 24h
const BLOOM_REFRESH_ALARM = "bloom_refresh";
const API_BASE_URL_DEFAULT = "http://127.0.0.1:8000";
const BLOOM_SIZE = 8192;
const BLOOM_HASH_COUNT = 7;

const bloomFilter = new BloomFilter(BLOOM_SIZE, BLOOM_HASH_COUNT);

function normalizeDomain(domain) {
  return String(domain || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

function getRiskLevel(score) {
  if (score <= 20) return "SAFE";
  if (score <= 40) return "LOW";
  if (score <= 60) return "MEDIUM";
  if (score <= 80) return "HIGH";
  return "CRITICAL";
}

function normalizeServerRiskLevel(value, fallbackScore = 0) {
  const level = String(value || "").toLowerCase();
  if (!level) return getRiskLevel(fallbackScore);
  if (level.includes("critical") || level.includes("çok tehlikeli")) return "CRITICAL";
  if (level.includes("high") || level.includes("tehlikeli")) return "HIGH";
  if (level.includes("medium") || level.includes("riskli") || level.includes("şüpheli") || level.includes("supheli")) return "MEDIUM";
  if (level.includes("low")) return "LOW";
  if (level.includes("safe") || level.includes("güvenli") || level.includes("guvenli")) return "SAFE";
  return getRiskLevel(fallbackScore);
}

function uniqueFlags(flags) {
  return [...new Set(flags)];
}

function combineRiskScores(domainScore, formScore) {
  return Math.min(100, Number(domainScore || 0) + Number(formScore || 0));
}

function isHttpUrl(url) {
  if (typeof url !== "string") return false;
  return url.startsWith("http://") || url.startsWith("https://");
}

function isBloomMatch(domain) {
  if (!domain) return false;
  if (bloomFilter.mightContain(domain)) return true;

  const labels = domain.split(".").filter(Boolean);
  for (let i = 1; i < labels.length - 1; i += 1) {
    const suffix = labels.slice(i).join(".");
    if (bloomFilter.mightContain(suffix)) return true;
  }
  return false;
}

async function getApiBaseUrl() {
  const stored = await chrome.storage.local.get(["api_base_url"]);
  const configured = String(stored.api_base_url || "").trim();
  const baseUrl = configured || API_BASE_URL_DEFAULT;
  return baseUrl.replace(/\/+$/g, "");
}

async function getServerRequestHeaders() {
  const stored = await chrome.storage.local.get(["aegis_key"]);
  const headers = { "Content-Type": "application/json" };
  const aegisKey = String(stored.aegis_key || "").trim();
  if (aegisKey) {
    headers["X-AegisNexus-Key"] = aegisKey;
  }
  return headers;
}

async function readDomainCache() {
  const stored = await chrome.storage.local.get([DOMAIN_CACHE_KEY]);
  const cache = stored[DOMAIN_CACHE_KEY];
  return cache && typeof cache === "object" ? cache : {};
}

async function writeDomainCache(cache) {
  await chrome.storage.local.set({ [DOMAIN_CACHE_KEY]: cache });
}

function buildDomainCacheKey(domain, url) {
  const normalizedDomain = normalizeDomain(domain);
  const rawUrl = String(url || "").trim();
  if (!rawUrl) return normalizedDomain;
  try {
    const parsed = new URL(rawUrl);
    const normalizedUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`;
    return `${normalizedDomain}::${normalizedUrl}`;
  } catch {
    return `${normalizedDomain}::${rawUrl}`;
  }
}

async function getCachedDomainResult(domain, url) {
  const cache = await readDomainCache();
  const cacheKey = buildDomainCacheKey(domain, url);
  const entry = cache[cacheKey];

  if (!entry || typeof entry !== "object") return null;

  const cachedAt = Number(entry.cachedAt || 0);
  if (!cachedAt || Date.now() - cachedAt > DOMAIN_CACHE_TTL_MS) {
    delete cache[cacheKey];
    await writeDomainCache(cache);
    return null;
  }
  return entry.result || null;
}

async function setCachedDomainResult(domain, url, result) {
  const cache = await readDomainCache();
  const cacheKey = buildDomainCacheKey(domain, url || result?.url);
  cache[cacheKey] = {
    cachedAt: Date.now(),
    result,
  };
  await writeDomainCache(cache);
}

async function loadBloomFromStorage() {
  const loaded = await bloomFilter.loadFromStorage();
  if (!loaded) {
    await bloomFilter.saveToStorage();
  }
}

function resetBloomFilter() {
  bloomFilter.bitArray = new Uint8Array(bloomFilter.size);
}

async function refreshBloomDomains() {
  const apiBaseUrl = await getApiBaseUrl();
  const response = await fetch(`${apiBaseUrl}/api/v2/phishing/export-domains`, {
    method: "GET",
    headers: await getServerRequestHeaders(),
  });
  if (!response.ok) return false;

  const text = await response.text();
  const domains = text
    .split("\n")
    .map((line) => normalizeDomain(line))
    .filter(Boolean);
  if (domains.length === 0) return false;

  resetBloomFilter();
  bloomFilter.loadFromArray(domains);
  await bloomFilter.saveToStorage();
  return true;
}

function getSafeDnsResult() {
  return {
    cloudflare_blocked: false,
    quad9_blocked: false,
    consensus_blocked: false,
    source: "server_dns",
  };
}

function getSafeGsbResult() {
  return {
    threat_found: false,
    threat_type: null,
    source: "server_gsb",
    available: false,
  };
}

async function runServerUrlCheck(url, domain, options = {}) {
  const dbOnly = options.dbOnly === true;
  const forceFresh = options.forceFresh === true;
  const localPayload = options.localPayload && typeof options.localPayload === "object" ? options.localPayload : {};
  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/phishing/check-url`;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: await getServerRequestHeaders(),
      body: JSON.stringify({
        url,
        domain,
        force_fresh: forceFresh,
        db_only: dbOnly,
        ...localPayload,
      }),
    });

    let data = null;
    try {
      data = await response.json();
    } catch {}

    return {
      requested: true,
      ok: response.ok,
      status: response.status,
      data,
    };
  } catch (error) {
    return {
      requested: true,
      ok: false,
      error: String(error),
    };
  }
}


async function resolveDomainIP(domain) {
  try {
    // Try to resolve domain to IP via DNS API (using chrome extension capabilities)
    // As a fallback, we'll attempt via fetch (may be blocked by CORS)
    const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
      headers: { "Accept": "application/dns-json" }
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    if (data.Answer && Array.isArray(data.Answer)) {
      for (const answer of data.Answer) {
        if (answer.type === 1) { // A record
          return answer.data;
        }
      }
    }
    return null;
  } catch (error) {
    console.warn(`IP resolution for ${domain} failed:`, error);
    return null;
  }
}

async function checkIOCIP(ip) {
  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/ioc/check-ip?ip=${encodeURIComponent(ip)}`;
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: await getServerRequestHeaders(),
    });

    let data = null;
    try {
      data = await response.json();
    } catch {}

    return {
      checked: response.ok,
      ok: response.ok,
      status: response.status,
      data,
    };
  } catch (error) {
    return {
      checked: false,
      ok: false,
      error: String(error),
    };
  }
}

async function checkIOCDomain(domain) {
  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/ioc/check-domain?domain=${encodeURIComponent(domain)}`;
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: await getServerRequestHeaders(),
    });

    let data = null;
    try {
      data = await response.json();
    } catch {}

    return {
      checked: response.ok,
      ok: response.ok,
      status: response.status,
      data,
    };
  } catch (error) {
    return {
      checked: false,
      ok: false,
      error: String(error),
    };
  }
}

async function checkDomain(domain, url, options = {}) {
  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedDomain || !isHttpUrl(url)) {
    return {
      domain: normalizedDomain,
      url,
      score: 0,
      flags: ["invalid-input"],
      risk_level: "SAFE",
      decision: "safe",
      cache_hit: false,
    };
  }

  if (await isWhitelisted(normalizedDomain)) {
    return {
      safe: true,
      source: "whitelist",
      domain: normalizedDomain,
      host: normalizedDomain,
      url,
      score: 0,
      flags: ["whitelisted-domain"],
      risk_level: "SAFE",
      decision: "safe",
      cache_hit: false,
    };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    parsedUrl = null;
  }

  const forceScan = options.forceScan === true;
  const cached = forceScan ? null : await getCachedDomainResult(normalizedDomain, url);
  if (cached && !forceScan) {
    return { ...cached, cache_hit: true };
  }

  const bloomMatched = isBloomMatch(normalizedDomain);
  const [dnsSettled, gsbSettled] = await Promise.allSettled([
    checkDomainViaDNS(normalizedDomain),
    checkGoogleSafeBrowsing(url),
  ]);
  const dnsResult = dnsSettled.status === "fulfilled" && dnsSettled.value && typeof dnsSettled.value === "object"
    ? {
      cloudflare_blocked: Boolean(dnsSettled.value.cloudflare_blocked),
      quad9_blocked: Boolean(dnsSettled.value.quad9_blocked),
      consensus_blocked: Boolean(dnsSettled.value.consensus_blocked),
      source: String(dnsSettled.value.source || "dns"),
    }
    : getSafeDnsResult();
  const gsbResult = gsbSettled.status === "fulfilled" && gsbSettled.value && typeof gsbSettled.value === "object"
    ? {
      threat_found: Boolean(gsbSettled.value.threat_found),
      threat_type: gsbSettled.value.threat_type || null,
      available: !Boolean(gsbSettled.value.skipped),
      skipped: Boolean(gsbSettled.value.skipped),
      source: String(gsbSettled.value.source || "gsb"),
    }
    : getSafeGsbResult();

  const heuristicResult = analyzeURL(url, {
    bloomMatched,
    dnsResult,
    gsbResult,
  });
  const localScore = Number.isFinite(Number(heuristicResult.score)) ? Math.max(0, Math.min(100, Number(heuristicResult.score))) : 0;
  const localFlags = Array.isArray(heuristicResult.flags) ? heuristicResult.flags.map((f) => String(f)) : [];
  const localRiskLevel = String(heuristicResult.risk_level || getRiskLevel(localScore)).toUpperCase();

  const localResult = {
    domain: normalizedDomain,
    host: normalizedDomain,
    url,
    https: parsedUrl?.protocol === "https:",
    score: localScore,
    flags: uniqueFlags(localFlags),
    risk_level: localRiskLevel,
    cache_hit: false,
    decision: "local_fallback",
    source: "local",
    is_phishing: localScore >= 60,
    heuristic: {
      source: "local",
      risk_level_raw: localRiskLevel,
      details: localFlags,
    },
    bloom: { matched: bloomMatched, source: "bloom" },
    dns: dnsResult,
    gsb: gsbResult,
  };

  const fullScan = await runServerUrlCheck(url, normalizedDomain, {
    dbOnly: false,
    forceFresh: forceScan,
    localPayload: {
      local_score: localScore,
      risk_level: localRiskLevel,
      flags: localFlags,
      dns: dnsResult,
      gsb: gsbResult,
      bloom: { matched: bloomMatched, source: "bloom" },
    },
  });

  if (!fullScan.ok || !fullScan.data || typeof fullScan.data !== "object") {
    await setCachedDomainResult(normalizedDomain, url, localResult);
    return localResult;
  }

  const serverData = fullScan.data?.data && typeof fullScan.data.data === "object" ? fullScan.data.data : fullScan.data;
  let serverScore = Number(serverData.score ?? localScore);
  if (!Number.isFinite(serverScore)) serverScore = localScore;
  serverScore = Math.max(0, Math.min(100, serverScore));

  const serverFlags = Array.isArray(serverData.flags) ? serverData.flags.map((item) => String(item)) : localFlags;
  const serverRiskLevel = normalizeServerRiskLevel(serverData.risk_level, serverScore);
  const mergedResult = {
    domain: normalizedDomain,
    host: normalizedDomain,
    url,
    https: parsedUrl?.protocol === "https:",
    score: serverScore,
    flags: uniqueFlags(serverFlags),
    risk_level: serverRiskLevel,
    cache_hit: false,
    decision: String(serverData.decision || "server_merged"),
    source: String(serverData.source || "server"),
    is_phishing: Boolean(serverData.is_phishing),
    heuristic: {
      source: "local",
      risk_level_raw: localRiskLevel,
      details: localFlags,
    },
    bloom: serverData.bloom && typeof serverData.bloom === "object" ? serverData.bloom : { matched: bloomMatched, source: "bloom" },
    dns: serverData.dns && typeof serverData.dns === "object" ? serverData.dns : dnsResult,
    gsb: serverData.gsb && typeof serverData.gsb === "object" ? serverData.gsb : gsbResult,
    layer3: fullScan,
  };

  await setCachedDomainResult(normalizedDomain, url, mergedResult);
  return mergedResult;
}

chrome.runtime.onInstalled.addListener(async () => {
  chrome.alarms.create(BLOOM_REFRESH_ALARM, { periodInMinutes: 1440 });
  await loadBloomFromStorage();
  await initializeWhitelistRefresh();
});

chrome.runtime.onStartup.addListener(async () => {
  chrome.alarms.create(BLOOM_REFRESH_ALARM, { periodInMinutes: 1440 });
  await loadBloomFromStorage();
  await initializeWhitelistRefresh();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== BLOOM_REFRESH_ALARM) return;
  refreshBloomDomains().catch((error) => {
    console.warn("AegisNexus Shield: bloom refresh failed", error);
  });
});

async function showDomainRiskNotification(domain, riskLevel, score, tabId, source = "scan") {
  try {
    const dismissedData = await chrome.storage.local.get([`dismissed:${domain}`]);
    if (dismissedData[`dismissed:${domain}`]) return;

    const sourceMessage = source === "database"
      ? "Bu site veritabanında tehlikeli olarak kayıtlı"
      : "Bu site tarama sonucu tehlikeli tespit edildi";

    const notifId = `aegis-${Date.now()}`;
    await chrome.storage.local.set({
      [`notif_tab:${notifId}`]: tabId,
      [`notif_domain:${notifId}`]: domain,
    });

    await chrome.notifications.create(notifId, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: `⚠️ AegisNexus Shield — ${riskLevel}`,
      message: `${sourceMessage}\n${domain} | Skor: ${score}`,
      priority: 2,
      buttons: [
        { title: "🔙 Geri Dön" },
        { title: "⚠️ Yine de Devam Et" }
      ]
    });
  } catch (err) {
    console.error("AegisNexus notification error:", err);
  }
}

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  const handleButtonClick = async () => {
    if (buttonIndex === 0) {
      const tabId = await chrome.storage.local.get([`notif_tab:${notificationId}`]);
      const tid = tabId[`notif_tab:${notificationId}`];
      if (tid) {
        chrome.tabs
          .sendMessage(tid, { type: "go_back" })
          .catch(() => {});
      }
    } else if (buttonIndex === 1) {
      const domainData = await chrome.storage.local.get([`notif_domain:${notificationId}`]);
      const domain = domainData[`notif_domain:${notificationId}`];
      if (domain) {
        await chrome.storage.local.set({ [`dismissed:${domain}`]: true });
      }
    }
    chrome.notifications.clear(notificationId).catch(() => {});
  };
  handleButtonClick().catch(() => {});
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url || !isHttpUrl(details.url)) return;

  let parsed;
  try {
    parsed = new URL(details.url);
  } catch {
    return;
  }
  
  console.log("LISTENER TETIKLENDI:", details.url);
  const domain = normalizeDomain(parsed.hostname);

  try {
    const result = await checkDomain(domain, details.url);

    await chrome.storage.local.set({
      lastScan: { ...result, scannedAt: Date.now() }
    });

    const riskLevel = String(result.risk_level || "SAFE").toUpperCase();
    if (riskLevel === "SAFE" || riskLevel === "LOW") return;

    const isDbFirstHit = result?.db_fast_path === true;
    if (isDbFirstHit) {
      if (riskLevel !== "HIGH" && riskLevel !== "CRITICAL") {
        return;
      }
      await showDomainRiskNotification(domain, riskLevel, result.score, details.tabId, "database");
      chrome.tabs.sendMessage(details.tabId, {
        type: "show_warning",
        risk_level: riskLevel,
        score: result.score,
        flags: result.flags,
      }).catch(() => {});
      return;
    }

    await showDomainRiskNotification(domain, riskLevel, result.score, details.tabId, "scan");
    if (riskLevel === "HIGH" || riskLevel === "CRITICAL") {
      chrome.tabs.sendMessage(details.tabId, {
        type: "show_warning",
        risk_level: riskLevel,
        score: result.score,
        flags: result.flags,
      }).catch(() => {});
    }

  } catch (error) {
    console.error("AegisNexus error:", error);
  }
});

async function reportFormToServer(domain, formData) {
  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/phishing/report-form`;
  try {
    await fetch(endpoint, {
      method: "POST",
      headers: await getServerRequestHeaders(),
      body: JSON.stringify({
        url: formData.url || "",
        domain,
        form_data: {
          action_url: formData.suspicious_forms?.[0]?.action_url || "",
          field_types: formData.suspicious_forms?.[0]?.field_types || formData.field_types || [],
          risk_score: formData.combined_risk_score || formData.highest_risk_score || 0,
          flags: formData.flags || [],
        },
      }),
    });
  } catch (error) {
    console.warn("AegisNexus Shield: form report failed", error);
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "get_result") {
    checkDomain(message.domain, message.url, { forceScan: false })
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "force_scan") {
    checkDomain(message.domain, message.url, { forceScan: true })
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "whitelist_add") {
    addToPersonalWhitelist(message.domain)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "whitelist_remove") {
    removeFromPersonalWhitelist(message.domain)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "form_detected") {
    const formData = message.form_data || {};
    const tabId = _sender?.tab?.id;
    const sourceUrl = formData.url || _sender?.tab?.url || "";
    let parsedUrl = null;
    try {
      parsedUrl = new URL(sourceUrl);
    } catch {}
    const domain = formData.domain || parsedUrl?.hostname || "";

    const processFormDetection = async () => {
      const domainResult = domain && sourceUrl ? await checkDomain(domain, sourceUrl) : { score: 0, flags: [] };
      const combinedRiskScore = combineRiskScores(domainResult.score, formData.highest_risk_score);
      const combinedRiskLevel = getRiskLevel(combinedRiskScore);
      const mergedFlags = uniqueFlags([...(domainResult.flags || []), ...(formData.flags || [])]);

      const combinedData = {
        ...formData,
        url: sourceUrl,
        domain,
        domain_score: Number(domainResult.score || 0),
        combined_risk_score: combinedRiskScore,
        combined_risk_level: combinedRiskLevel,
        flags: mergedFlags,
      };

      await chrome.storage.local.set({ lastFormScan: combinedData });

      if (tabId && (combinedRiskLevel === "HIGH" || combinedRiskLevel === "CRITICAL")) {
        const formIndices = (combinedData.suspicious_forms || [])
          .filter((item) => item.risk_level === "HIGH" || item.risk_level === "CRITICAL")
          .map((item) => item.form_index)
          .filter((value) => Number.isInteger(value));
        chrome.tabs
          .sendMessage(tabId, {
            type: "show_form_warning",
            form_indices: formIndices,
            form_data: combinedData,
          })
          .catch(() => {});
      }

      if (domain && (combinedRiskLevel === "HIGH" || combinedRiskLevel === "CRITICAL")) {
        await reportFormToServer(domain, combinedData);
      }
    };

    processFormDetection()
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "ANALYZE_URL") {
    const url = String(message.url || "");
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      sendResponse({
        ok: true,
        result: {
          score: 0,
          flags: ["invalid-url"],
          risk_level: "SAFE",
          url,
          domain: "",
        },
      });
      return false;
    }

    checkDomain(parsed.hostname, url)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "GET_LAST_SCAN") {
    chrome.storage.local
      .get(["lastScan"])
      .then((data) => sendResponse({ ok: true, lastScan: data.lastScan || null }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "CHECK_DOMAIN") {
    checkDomain(message.domain, message.url)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }
  return false;
});

initializeWhitelistRefresh().catch((error) => {
  console.warn("AegisNexus Shield: whitelist refresh init failed", error);
});
