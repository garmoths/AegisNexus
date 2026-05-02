import { analyzeURL } from "../utils/heuristic.js";
import { BloomFilter } from "../utils/bloom_filter.js";
import { checkDomainViaDNS } from "../utils/dns_check.js";
import { checkURL } from "../utils/gsb_check.js";
import { addToPersonalWhitelist, initializeWhitelistRefresh, isWhitelisted } from "../utils/whitelist.js";

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

function uniqueFlags(flags) {
  return [...new Set(flags)];
}

function isHttpUrl(url) {
  return /^https?:/i.test(String(url || ""));
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

async function readDomainCache() {
  const stored = await chrome.storage.local.get([DOMAIN_CACHE_KEY]);
  const cache = stored[DOMAIN_CACHE_KEY];
  return cache && typeof cache === "object" ? cache : {};
}

async function writeDomainCache(cache) {
  await chrome.storage.local.set({ [DOMAIN_CACHE_KEY]: cache });
}

async function getCachedDomainResult(domain) {
  const cache = await readDomainCache();
  const entry = cache[domain];
  if (!entry || typeof entry !== "object") return null;

  const cachedAt = Number(entry.cachedAt || 0);
  if (!cachedAt || Date.now() - cachedAt > DOMAIN_CACHE_TTL_MS) {
    delete cache[domain];
    await writeDomainCache(cache);
    return null;
  }
  return entry.result || null;
}

async function setCachedDomainResult(domain, result) {
  const cache = await readDomainCache();
  cache[domain] = {
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
    source: "dns",
  };
}

function getSafeGsbResult() {
  return {
    threat_found: false,
    threat_type: null,
    source: "gsb",
  };
}

async function runLayer3(url, domain) {
  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/phishing/check-url`;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url, domain }),
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
  const cached = forceScan ? null : await getCachedDomainResult(normalizedDomain);
  if (cached && !forceScan) {
    return { ...cached, cache_hit: true };
  }

  const heuristicBase = analyzeURL(url);
  let score = heuristicBase.score;
  const flags = [...heuristicBase.flags];

  const bloomMatched = isBloomMatch(normalizedDomain);
  if (bloomMatched) {
    score += 20;
    flags.push("bloom-suspect-domain");
  }

  const [dnsSettled, gsbSettled] = await Promise.allSettled([
    checkDomainViaDNS(normalizedDomain),
    checkURL(url),
  ]);
  const dnsResult = dnsSettled.status === "fulfilled" ? dnsSettled.value : getSafeDnsResult();
  const gsbResult = gsbSettled.status === "fulfilled" ? gsbSettled.value : getSafeGsbResult();

  if (dnsResult.consensus_blocked) {
    score += 40;
    flags.push("dns-consensus-blocked");
  } else if (dnsResult.cloudflare_blocked || dnsResult.quad9_blocked) {
    score += 20;
    flags.push("dns-provider-blocked");
  }

  if (gsbResult.threat_found === true) {
    score += 50;
    flags.push("gsb-threat");
  }

  score = Math.min(score, 100);
  const riskLevel = gsbResult.threat_found === true ? "CRITICAL" : getRiskLevel(score);
  const shouldRunLayer3 = score >= 70 || dnsResult.consensus_blocked === true || gsbResult.threat_found === true;
  const isSuspicious = !shouldRunLayer3 && score >= 40 && score <= 69;

  let layer3 = { requested: false };
  if (shouldRunLayer3) {
    layer3 = await runLayer3(url, normalizedDomain);
  }

  const result = {
    domain: normalizedDomain,
    host: normalizedDomain,
    url,
    https: parsedUrl?.protocol === "https:",
    score,
    flags: uniqueFlags(flags),
    risk_level: riskLevel,
    cache_hit: false,
    decision: shouldRunLayer3 ? "layer3_checked" : isSuspicious ? "suspicious" : "safe",
    heuristic: heuristicBase,
    bloom: { matched: bloomMatched, source: "bloom" },
    dns: dnsResult,
    gsb: gsbResult,
    layer3,
  };

  await setCachedDomainResult(normalizedDomain, result);
  return result;
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

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url || !isHttpUrl(details.url)) return;

  let parsed;
  try {
    parsed = new URL(details.url);
  } catch {
    return;
  }

  const domain = normalizeDomain(parsed.hostname);
  checkDomain(domain, details.url)
    .then((result) => {
      chrome.storage.local.set({
        lastScan: {
          ...result,
          scannedAt: Date.now(),
        },
      });
      if (result.risk_level !== "HIGH" && result.risk_level !== "CRITICAL") return;
      chrome.tabs
        .sendMessage(details.tabId, {
          type: "show_warning",
          risk_level: result.risk_level,
          score: result.score,
          flags: result.flags,
        })
        .catch(() => {});
    })
    .catch((error) => {
      console.warn("AegisNexus Shield: domain check failed", error);
    });
});

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
