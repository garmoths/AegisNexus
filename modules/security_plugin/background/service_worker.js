self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));

import { BloomFilter } from "../utils/bloom_filter.js";
import { addToPersonalWhitelist, removeFromPersonalWhitelist, initializeWhitelistRefresh, isWhitelisted } from "../utils/whitelist.js";

const DOMAIN_CACHE_KEY = "domain_cache";
const DOMAIN_CACHE_TTL_MS = 86400000; // 24h
const BLOOM_REFRESH_ALARM = "bloom_refresh";
const BLOOM_REFRESH_MINUTES = 30;
const API_BASE_URL_DEFAULT = "http://127.0.0.1:8000";
const BLOOM_SIZE = 8192;
const BLOOM_HASH_COUNT = 7;
const URL_NOTIFICATION_COOLDOWN_KEY = "url_notification_cooldown";
const TRUSTED_DOMAIN_MUTE_KEY = "trusted_domain_mute_until";
const URL_NOTIFICATION_COOLDOWN_MS = 12 * 60 * 60 * 1000; // 12 saat
const TRUSTED_DOMAIN_MUTE_MS = 30 * 24 * 60 * 60 * 1000; // 30 gün

const bloomFilter = new BloomFilter(BLOOM_SIZE, BLOOM_HASH_COUNT);
let bloomRefreshedOnFirstNavigation = false;
let fallbackModulesPromise = null;

async function loadFallbackModules() {
  if (!fallbackModulesPromise) {
    fallbackModulesPromise = Promise.all([
      import("../utils/heuristic.js"),
      import("../utils/dns_check.js"),
      import("../utils/gsb_check.js"),
    ])
      .then(([heuristicModule, dnsModule, gsbModule]) => ({
        analyzeURL: heuristicModule.analyzeURL,
        checkDomainViaDNS: dnsModule.checkDomainViaDNS,
        checkGoogleSafeBrowsing: gsbModule.checkURL,
      }))
      .catch((error) => {
        fallbackModulesPromise = null;
        throw error;
      });
  }
  return fallbackModulesPromise;
}

function normalizeDomain(domain) {
  return String(domain || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

function getRiskLevel(safetyScore) {
  // Yeni skor bandları: 0-20 kritik, 20-40 riskli, 40-60 orta, 60-80 iyi, 80-100 güvenilir
  if (safetyScore >= 80) return "GÜVENLİ";
  if (safetyScore >= 60) return "İYİ";
  if (safetyScore >= 40) return "ORTA";
  if (safetyScore >= 20) return "RİSKLİ";
  return "KRİTİK";
}

function getRiskLevelFromRiskScore(riskScore) {
  if (riskScore >= 80) return "GÜVENLİ";
  if (riskScore >= 60) return "İYİ";
  if (riskScore >= 40) return "ORTA";
  if (riskScore >= 20) return "RİSKLİ";
  return "KRİTİK";
}

function normalizeServerRiskLevel(value, fallbackSafetyScore = 0) {
  const level = String(value || "").toLowerCase();
  if (level.includes("kritik") || level.includes("critical") || level.includes("çok tehlikeli")) return "KRİTİK";
  if (level.includes("riskli") || level.includes("yüksek") || level.includes("yuksek") || level.includes("high") || level.includes("tehlikeli")) return "RİSKLİ";
  if (level.includes("orta") || level.includes("medium") || level.includes("şüpheli") || level.includes("supheli")) return "ORTA";
  if (level.includes("iyi") || level.includes("good")) return "İYİ";
  if (level.includes("düşük") || level.includes("dusuk") || level.includes("low") || level.includes("güvenli") || level.includes("guvenli") || level.includes("safe")) return "GÜVENLİ";
  return getRiskLevel(fallbackSafetyScore);
}

function uniqueFlags(flags) {
  return [...new Set(flags)];
}

function combineRiskScores(domainScore, formScore) {
  const domainSafety = Math.max(0, Math.min(100, Number(domainScore || 0)));
  const domainRisk = 100 - domainSafety;
  return Math.min(100, domainRisk + Number(formScore || 0));
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

function buildNotificationUrlKey(url, domainFallback = "") {
  const rawUrl = String(url || "").trim();
  if (!rawUrl) return normalizeDomain(domainFallback);
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`.toLowerCase();
  } catch {
    return rawUrl.toLowerCase();
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

async function isDomainNotificationMuted(domain) {
  const clean = normalizeDomain(domain);
  if (!clean) return false;
  const stored = await chrome.storage.local.get([TRUSTED_DOMAIN_MUTE_KEY]);
  const map = stored[TRUSTED_DOMAIN_MUTE_KEY] && typeof stored[TRUSTED_DOMAIN_MUTE_KEY] === "object"
    ? stored[TRUSTED_DOMAIN_MUTE_KEY]
    : {};
  return Number(map[clean] || 0) > Date.now();
}

async function setDomainNotificationMute(domain, durationMs = TRUSTED_DOMAIN_MUTE_MS) {
  const clean = normalizeDomain(domain);
  if (!clean) return;
  const stored = await chrome.storage.local.get([TRUSTED_DOMAIN_MUTE_KEY]);
  const map = stored[TRUSTED_DOMAIN_MUTE_KEY] && typeof stored[TRUSTED_DOMAIN_MUTE_KEY] === "object"
    ? stored[TRUSTED_DOMAIN_MUTE_KEY]
    : {};
  map[clean] = Date.now() + durationMs;
  await chrome.storage.local.set({ [TRUSTED_DOMAIN_MUTE_KEY]: map });
}

async function isUrlNotificationCooling(url, domain) {
  const key = buildNotificationUrlKey(url, domain);
  if (!key) return false;
  const stored = await chrome.storage.local.get([URL_NOTIFICATION_COOLDOWN_KEY]);
  const map = stored[URL_NOTIFICATION_COOLDOWN_KEY] && typeof stored[URL_NOTIFICATION_COOLDOWN_KEY] === "object"
    ? stored[URL_NOTIFICATION_COOLDOWN_KEY]
    : {};
  return Number(map[key] || 0) > Date.now();
}

async function setUrlNotificationCooldown(url, domain, durationMs = URL_NOTIFICATION_COOLDOWN_MS) {
  const key = buildNotificationUrlKey(url, domain);
  if (!key) return;
  const stored = await chrome.storage.local.get([URL_NOTIFICATION_COOLDOWN_KEY]);
  const map = stored[URL_NOTIFICATION_COOLDOWN_KEY] && typeof stored[URL_NOTIFICATION_COOLDOWN_KEY] === "object"
    ? stored[URL_NOTIFICATION_COOLDOWN_KEY]
    : {};
  map[key] = Date.now() + durationMs;
  await chrome.storage.local.set({ [URL_NOTIFICATION_COOLDOWN_KEY]: map });
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

async function runDbLookup(url) {
  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/phishing/db-lookup?url=${encodeURIComponent(url)}`;
  try {
    const response = await fetch(endpoint, { headers: await getServerRequestHeaders() });
    if (!response.ok) return { found: false };
    const data = await response.json();
    return data && typeof data === "object" ? data : { found: false };
  } catch {
    return { found: false };
  }
}

async function pollJobResult(jobId, maxWaitMs = 45000) {
  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/phishing/result/${encodeURIComponent(jobId)}`;
  const interval = 2000;
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, interval));
    try {
      const response = await fetch(endpoint, { headers: await getServerRequestHeaders() });
      if (!response.ok) continue;
      const data = await response.json();
      if (data && data.status !== "pending") return { ok: true, data };
    } catch {}
  }
  return { ok: false, timeout: true };
}

async function runDeepScanFlow(url, domain) {
  // Adım 1: Chrome local cache
  const normalizedDomain = normalizeDomain(domain);
  const cached = await getCachedDomainResult(normalizedDomain, url);
  if (cached) {
    return { ...cached, deep_scan_source: "cache", cache_hit: true };
  }

  // Adım 2: Backend SQLite db-lookup
  const dbResult = await runDbLookup(url);
  if (dbResult.found) {
    const dbSafetyScore = Math.max(0, Math.min(100, Number(dbResult.risk_score || 0)));
    const dbRiskLevel = normalizeServerRiskLevel(dbResult.risk_level, dbSafetyScore);
    const merged = {
      domain: normalizedDomain,
      url,
      score: dbSafetyScore,
      risk_level: dbRiskLevel,
      is_phishing: dbSafetyScore < 40,
      is_safe: Boolean(dbResult.is_safe),
      flags: [],
      sources: Array.isArray(dbResult.sources) ? dbResult.sources.map((s) => ({ name: s, status: "db" })) : [],
      decision: "db_hit",
      source: "db",
      cache_hit: false,
      deep_scan_source: "db",
      db_last_updated: dbResult.last_updated || null,
    };
    await setCachedDomainResult(normalizedDomain, url, merged);
    return merged;
  }

  // Adım 3: Backend check-url (force_fresh)
  const fullScan = await runServerUrlCheck(url, normalizedDomain, { forceFresh: true });
  if (!fullScan.ok || !fullScan.data || typeof fullScan.data !== "object") {
    return null;
  }

  const serverData = fullScan.data?.data && typeof fullScan.data.data === "object" ? fullScan.data.data : fullScan.data;

  // Adım 3b: Celery kuyruğa alındıysa polling
  if (serverData.status === "analyzing" && serverData.job_id) {
    const polled = await pollJobResult(serverData.job_id);
    if (polled.ok && polled.data) {
      const d = polled.data?.data && typeof polled.data.data === "object" ? polled.data.data : polled.data;
      const safeScore = Math.max(0, Math.min(100, Number(d.score ?? d.safety_score ?? 50)));
      const riskLevel = normalizeServerRiskLevel(d.risk_level, safeScore);
      const result = {
        ...d,
        score: safeScore,
        risk_level: riskLevel,
        is_phishing: safeScore < 40,
        deep_scan_source: "api_celery",
        source: "server",
      };
      await setCachedDomainResult(normalizedDomain, url, result);
      return result;
    }
    const timeoutSafetyScore = Math.max(0, Math.min(100, Number(serverData.score ?? 50)));
    return {
      ...serverData,
      score: timeoutSafetyScore,
      risk_level: normalizeServerRiskLevel(serverData.risk_level, timeoutSafetyScore),
      is_phishing: timeoutSafetyScore < 40,
      deep_scan_source: "api_celery_timeout",
      source: "server",
    };
  }

  // Adım 3a: Senkron sonuç
  let serverScore = Number(serverData.score ?? serverData.safety_score ?? 0);
  serverScore = Math.max(0, Math.min(100, serverScore));
  const riskLevel = normalizeServerRiskLevel(serverData.risk_level, serverScore);
  const result = {
    ...serverData,
    score: serverScore,
    risk_level: riskLevel,
    is_phishing: serverScore < 40,
    deep_scan_source: "api",
    source: "server",
  };
  await setCachedDomainResult(normalizedDomain, url, result);
  return result;
}

async function runLocalFallbackScan(normalizedDomain, url, parsedUrl) {
  let fallbackModules;
  try {
    fallbackModules = await loadFallbackModules();
  } catch (error) {
    console.warn("AegisNexus Shield: fallback modules failed to load", error);
    return {
      domain: normalizedDomain,
      host: normalizedDomain,
      url,
      https: parsedUrl?.protocol === "https:",
      score: 0,
      flags: ["local-fallback-unavailable"],
      risk_level: "GÜVENLİ",
      cache_hit: false,
      decision: "local_fallback_error",
      source: "local",
      is_phishing: false,
      heuristic: {
        source: "local",
        risk_level_raw: "GÜVENLİ",
        details: ["local-fallback-unavailable"],
      },
      bloom: { matched: false, source: "bloom" },
      dns: getSafeDnsResult(),
      gsb: getSafeGsbResult(),
    };
  }

  const bloomMatched = isBloomMatch(normalizedDomain);
  const [dnsSettled, gsbSettled] = await Promise.allSettled([
    fallbackModules.checkDomainViaDNS(normalizedDomain),
    fallbackModules.checkGoogleSafeBrowsing(url),
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

  const heuristicResult = fallbackModules.analyzeURL(url, {
    bloomMatched,
    dnsResult,
    gsbResult,
  });

  const localSafetyScore = Number.isFinite(Number(heuristicResult.score))
    ? Math.max(0, Math.min(100, Number(heuristicResult.score)))
    : 0;
  const localFlags = Array.isArray(heuristicResult.flags) ? heuristicResult.flags.map((f) => String(f)) : [];
  const localRiskLevel = String(heuristicResult.risk_level || getRiskLevel(localSafetyScore));

  return {
    domain: normalizedDomain,
    host: normalizedDomain,
    url,
    https: parsedUrl?.protocol === "https:",
    score: localSafetyScore,
    flags: uniqueFlags(localFlags),
    risk_level: localRiskLevel,
    cache_hit: false,
    decision: "local_fallback",
    source: "local",
    is_phishing: localSafetyScore < 40,
    heuristic: {
      source: "local",
      risk_level_raw: localRiskLevel,
      details: localFlags,
    },
    bloom: { matched: bloomMatched, source: "bloom" },
    dns: dnsResult,
    gsb: gsbResult,
  };
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
      risk_level: "GÜVENLİ",
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
      score: 100,
      flags: ["whitelisted-domain"],
      risk_level: "GÜVENLİ",
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

  // HIZLI HEURISTIK: Sadece bloom ile anında çalışır, DNS/GSB beklemez (~0ms)
  const bloomMatched = isBloomMatch(normalizedDomain);
  const heuristicResult = analyzeURL(url, { bloomMatched });
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
    dns: getSafeDnsResult(),
    gsb: getSafeGsbResult(),
  };

  // NORMAL TARAMA: hemen dön, DNS/GSB arka planda
  if (!forceScan) {
    await setCachedDomainResult(normalizedDomain, url, localResult);
    Promise.allSettled([checkDomainViaDNS(normalizedDomain), checkGoogleSafeBrowsing(url)])
      .then(async ([dnsS, gsbS]) => {
        const dnsR = dnsS.status === "fulfilled" && dnsS.value ? dnsS.value : getSafeDnsResult();
        const gsbR = gsbS.status === "fulfilled" && gsbS.value ? gsbS.value : getSafeGsbResult();
        runServerUrlCheck(url, normalizedDomain, {
          dbOnly: false, forceFresh: false,
          localPayload: { local_score: localScore, risk_level: localRiskLevel, flags: localFlags, dns: dnsR, gsb: gsbR, bloom: { matched: bloomMatched, source: "bloom" } },
        }).catch(() => {});
      }).catch(() => {});
    return localResult;
  }

  // DERIN TARAMA: önce DB kontrolü
  const dbCheck = await runServerUrlCheck(url, normalizedDomain, { dbOnly: true, forceFresh: false, localPayload: {} });
  if (dbCheck.ok && dbCheck.data && typeof dbCheck.data === "object") {
    const dbData = dbCheck.data?.data || dbCheck.data;
    if (dbData.score !== undefined || dbData.risk_level) {
      const cr = { ...localResult,
        score: Number(dbData.score ?? localScore),
        risk_level: normalizeServerRiskLevel(dbData.risk_level, dbData.score ?? localScore),
        flags: uniqueFlags([...localFlags, ...(Array.isArray(dbData.flags) ? dbData.flags : [])]),
        decision: "db_cached", source: "database", is_phishing: Boolean(dbData.is_phishing), db_fast_path: true };
      await setCachedDomainResult(normalizedDomain, url, cr);
      return cr;
    }
  }

  // DB'de yok → DNS + GSB + curl
  const [dnsSettled, gsbSettled] = await Promise.allSettled([
    checkDomainViaDNS(normalizedDomain), checkGoogleSafeBrowsing(url)]);
  const dnsResult = dnsSettled.status === "fulfilled" && dnsSettled.value ? {
    cloudflare_blocked: !!dnsSettled.value.cloudflare_blocked, quad9_blocked: !!dnsSettled.value.quad9_blocked,
    consensus_blocked: !!dnsSettled.value.consensus_blocked, source: String(dnsSettled.value.source || "dns") } : getSafeDnsResult();
  const gsbResult = gsbSettled.status === "fulfilled" && gsbSettled.value ? {
    threat_found: !!gsbSettled.value.threat_found, threat_type: gsbSettled.value.threat_type || null,
    available: !gsbSettled.value.skipped, skipped: !!gsbSettled.value.skipped, source: String(gsbSettled.value.source || "gsb") } : getSafeGsbResult();

  const fullHeuristic = analyzeURL(url, { bloomMatched, dnsResult, gsbResult });
  const fullScore = Number.isFinite(Number(fullHeuristic.score)) ? Math.max(0, Math.min(100, Number(fullHeuristic.score))) : localScore;

  const fullScan = await runServerUrlCheck(url, normalizedDomain, {
    dbOnly: false, forceFresh: true,
    localPayload: { local_score: fullScore, risk_level: String(fullHeuristic.risk_level || getRiskLevel(fullScore)).toUpperCase(),
      flags: uniqueFlags([...localFlags, ...(Array.isArray(fullHeuristic.flags) ? fullHeuristic.flags : [])]),
      dns: dnsResult, gsb: gsbResult, bloom: { matched: bloomMatched, source: "bloom" } },
  });

  if (!fullScan.ok || !fullScan.data || typeof fullScan.data !== "object") {
    const fallback = { ...localResult, score: fullScore, dns: dnsResult, gsb: gsbResult,
      flags: uniqueFlags([...localFlags, ...(Array.isArray(fullHeuristic.flags) ? fullHeuristic.flags : [])]),
      risk_level: String(fullHeuristic.risk_level || getRiskLevel(fullScore)).toUpperCase() };
    await setCachedDomainResult(normalizedDomain, url, fallback);
    return fallback;
  }

  const serverData = fullScan.data?.data || fullScan.data;
  let serverScore = Number(serverData.score ?? fullScore);
  if (!Number.isFinite(serverScore)) serverScore = fullScore;
  serverScore = Math.max(0, Math.min(100, serverScore));
  const serverFlags = Array.isArray(serverData.flags) ? serverData.flags.map((item) => String(item)) : [];
  const serverRiskLevel = normalizeServerRiskLevel(serverData.risk_level, serverScore);
  const mergedResult = {
    domain: normalizedDomain, host: normalizedDomain, url,
    https: parsedUrl?.protocol === "https:",
    score: serverScore,
    flags: uniqueFlags([...serverFlags, ...(Array.isArray(fullHeuristic.flags) ? fullHeuristic.flags : [])]),
    risk_level: normalizeServerRiskLevel(serverData.risk_level, serverScore),
    cache_hit: false,
    decision: String(serverData.decision || "server_merged"),
    source: String(serverData.source || "server"),
    is_phishing: serverScore < 40,
    heuristic: serverData.heuristic && typeof serverData.heuristic === "object"
      ? serverData.heuristic
      : { source: "server", details: Array.isArray(serverData.details) ? serverData.details : [] },
    bloom: serverData.bloom && typeof serverData.bloom === "object" ? serverData.bloom : { matched: false, source: "server" },
    dns: serverData.dns && typeof serverData.dns === "object" ? serverData.dns : getSafeDnsResult(),
    gsb: serverData.gsb && typeof serverData.gsb === "object" ? serverData.gsb : getSafeGsbResult(),
    layer3: fullScan,
    db_match: Boolean(serverData.db_match),
    db_risk_score: serverData.db_match ? Number(serverData.db_risk_score || 0) : null,
    db_risk_level: serverData.db_risk_level || null,
    db_is_safe: serverData.db_is_safe ?? null,
    db_last_updated: serverData.db_last_updated || null,
  };
  await setCachedDomainResult(normalizedDomain, url, mergedResult);
  return mergedResult;
}

chrome.runtime.onInstalled.addListener(async () => {
  chrome.alarms.create(BLOOM_REFRESH_ALARM, { periodInMinutes: BLOOM_REFRESH_MINUTES });
  await loadBloomFromStorage();
  await initializeWhitelistRefresh();
  
  // Cache'i temizle
  await chrome.storage.local.remove([DOMAIN_CACHE_KEY]);
});

chrome.runtime.onStartup.addListener(async () => {
  chrome.alarms.create(BLOOM_REFRESH_ALARM, { periodInMinutes: BLOOM_REFRESH_MINUTES });
  await loadBloomFromStorage();
  await initializeWhitelistRefresh();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== BLOOM_REFRESH_ALARM) return;
  refreshBloomDomains().catch((error) => {
    console.warn("AegisNexus Shield: bloom refresh failed", error);
  });
});

async function showDomainRiskNotification(domain, riskLevel, score, tabId, source = "scan", pageUrl = "") {
  try {
    if (await isDomainNotificationMuted(domain)) return;
    if (await isUrlNotificationCooling(pageUrl, domain)) return;

    const sourceMessage = source === "database"
      ? "Bu site veritabanında tehlikeli olarak kayıtlı"
      : source === "server"
        ? "Bu site sunucu analizi sonucu tehlikeli tespit edildi"
      : "Bu site tarama sonucu tehlikeli tespit edildi";

    const notifId = `aegis-${Date.now()}`;
    await chrome.storage.local.set({
      [`notif_tab:${notifId}`]: tabId,
      [`notif_domain:${notifId}`]: domain,
      [`notif_url:${notifId}`]: buildNotificationUrlKey(pageUrl, domain),
    });

    await chrome.notifications.create(notifId, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: `⚠️ AegisNexus Shield — ${riskLevel}`,
      message: `${sourceMessage}\n${domain} | Güvenilirlik: ${score}/100`,
      priority: 2,
      buttons: [
        { title: "🔙 Geri Dön" },
        { title: "⚠️ Yine de Devam Et" }
      ]
    });
    await setUrlNotificationCooldown(pageUrl, domain);
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
        chrome.tabs.get(tid, (tab) => {
          if (chrome.runtime.lastError) return;
          chrome.tabs.update(tid, { url: "chrome://newtab" });
        });
      }
    } else if (buttonIndex === 1) {
      const domainData = await chrome.storage.local.get([`notif_domain:${notificationId}`]);
      const urlData = await chrome.storage.local.get([`notif_url:${notificationId}`]);
      const domain = domainData[`notif_domain:${notificationId}`];
      const notifUrl = String(urlData[`notif_url:${notificationId}`] || "");
      if (domain) await setUrlNotificationCooldown(notifUrl, domain);
    }
    chrome.notifications.clear(notificationId).catch(() => {});
  };
  handleButtonClick().catch(console.error);
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url || !isHttpUrl(details.url)) return;

  if (!bloomRefreshedOnFirstNavigation) {
    bloomRefreshedOnFirstNavigation = true;
    refreshBloomDomains().catch((error) => {
      console.warn("AegisNexus Shield: bloom first-navigation refresh failed", error);
    });
  }

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

    const riskLevel = String(result.risk_level || "GÜVENLİ");
    if (result.score >= 60) return;

    const isDbFirstHit = result?.db_fast_path === true;
    if (isDbFirstHit) {
      await showDomainRiskNotification(domain, riskLevel, result.score, details.tabId, "database", details.url);
      chrome.tabs.sendMessage(details.tabId, {
        type: "show_warning",
        risk_level: riskLevel,
        score: result.score,
        flags: result.flags,
      }).catch(() => {});
      return;
    }

    const resultSource = String(result?.source || "").toLowerCase();
    const notificationSource = resultSource.startsWith("server") ? "server" : "scan";
    await showDomainRiskNotification(domain, riskLevel, result.score, details.tabId, notificationSource, details.url);
    chrome.tabs.sendMessage(details.tabId, {
      type: "show_warning",
      risk_level: riskLevel,
      score: result.score,
      flags: result.flags,
    }).catch(() => {});

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

async function runServerFormRiskScore(url, domain, formData = {}) {
  const normalizedDomain = normalizeDomain(domain);
  const sourceUrl = String(url || "").trim();
  if (!normalizedDomain || !sourceUrl) {
    return { ok: false };
  }

  const fieldTypesFromForms = Array.isArray(formData.suspicious_forms)
    ? formData.suspicious_forms.flatMap((item) => (Array.isArray(item?.field_types) ? item.field_types : []))
    : [];
  const fieldTypes = uniqueFlags([
    ...(Array.isArray(formData.field_types) ? formData.field_types : []),
    ...fieldTypesFromForms,
  ]).map((item) => String(item));

  const inferredFormCount = Number(formData.form_count);
  const formCount = Number.isFinite(inferredFormCount) && inferredFormCount >= 0
    ? Math.floor(inferredFormCount)
    : (Array.isArray(formData.suspicious_forms) && formData.suspicious_forms.length > 0
      ? formData.suspicious_forms.length
      : 1);

  const apiBaseUrl = await getApiBaseUrl();
  const endpoint = `${apiBaseUrl}/api/v2/phishing/form-risk-score`;

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: await getServerRequestHeaders(),
      body: JSON.stringify({
        url: sourceUrl,
        domain: normalizedDomain,
        field_types: fieldTypes,
        form_count: formCount,
      }),
    });
    if (!response.ok) return { ok: false, status: response.status };

    const payload = await response.json();
    const data = payload?.data && typeof payload.data === "object" ? payload.data : payload;
    const riskScore = Number(data?.risk_score);
    if (!Number.isFinite(riskScore)) return { ok: false };

    return {
      ok: true,
      risk_score: Math.max(0, Math.min(100, riskScore)),
      risk_level: String(data?.risk_level || ""),
      flags: Array.isArray(data?.flags) ? data.flags.map((item) => String(item)) : [],
      source: String(data?.source || "server_form"),
    };
  } catch {
    return { ok: false };
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

  if (message?.type === "deep_scan") {
    runDeepScanFlow(message.url, message.domain)
      .then((result) => {
        if (!result) {
          sendResponse({ ok: false, error: "Derin tarama sonucu alınamadı" });
        } else {
          sendResponse({ ok: true, result });
        }
      })
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }

  if (message?.type === "whitelist_add") {
    addToPersonalWhitelist(message.domain)
      .then(async () => {
        await setDomainNotificationMute(message.domain);
        sendResponse({ ok: true });
      })
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
      const serverFormScore = domain && sourceUrl
        ? await runServerFormRiskScore(sourceUrl, domain, formData)
        : { ok: false };

      const combinedRiskScore = serverFormScore.ok
        ? Number(serverFormScore.risk_score || 0)
        : combineRiskScores(domainResult.score, formData.highest_risk_score);
      const combinedRiskLevel = serverFormScore.ok
        ? normalizeServerRiskLevel(serverFormScore.risk_level, 100 - combinedRiskScore)
        : getRiskLevelFromRiskScore(combinedRiskScore);
      const mergedFlags = uniqueFlags([
        ...(domainResult.flags || []),
        ...(formData.flags || []),
        ...(serverFormScore.ok ? (serverFormScore.flags || []) : []),
      ]);

      const combinedData = {
        ...formData,
        url: sourceUrl,
        domain,
        domain_score: Number(domainResult.score || 0),
        combined_risk_score: combinedRiskScore,
        combined_risk_level: combinedRiskLevel,
        form_score_source: serverFormScore.ok ? serverFormScore.source : "local_fallback",
        flags: mergedFlags,
      };

      await chrome.storage.local.set({ lastFormScan: combinedData });

      if (tabId && (combinedRiskLevel === "YÜKSEK" || combinedRiskLevel === "KRİTİK" || combinedRiskLevel === "HIGH" || combinedRiskLevel === "CRITICAL")) {
        const formIndices = (combinedData.suspicious_forms || [])
          .filter((item) => item.risk_level === "YÜKSEK" || item.risk_level === "KRİTİK" || item.risk_level === "HIGH" || item.risk_level === "CRITICAL")
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
          risk_level: "GÜVENLİ",
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
