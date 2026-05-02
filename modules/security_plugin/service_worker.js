import { analyzeURL } from "./utils/heuristic.js";
import { BloomFilter } from "./utils/bloom_filter.js";
import { checkDomainViaDNS } from "./utils/dns_check.js";
import { checkURL } from "./utils/gsb_check.js";

// Lightweight in-memory cache for the current session.
const sessionState = {
  alertsSent: new Set(),
};
const bloomFilter = new BloomFilter(8192, 7);
const DEFAULT_SUSPECT_DOMAINS = [
  "secure-update-account.xyz",
  "wallet-verify.top",
  "bank-login-check.tk",
  "account-security-alert.ml",
  "signin-validation.ga",
];

function isBloomSuspicious(hostname) {
  // Bloom filter is only a risk signal, never a blocking decision.
  const host = String(hostname || "").toLowerCase();
  if (!host) return false;
  if (bloomFilter.mightContain(host)) return true;

  const labels = host.split(".").filter(Boolean);
  for (let i = 1; i < labels.length - 1; i += 1) {
    const suffix = labels.slice(i).join(".");
    if (bloomFilter.mightContain(suffix)) return true;
  }
  return false;
}

async function initializeBloomFilter() {
  const loaded = await bloomFilter.loadFromStorage();
  if (loaded) return;

  bloomFilter.loadFromArray(DEFAULT_SUSPECT_DOMAINS);
  await bloomFilter.saveToStorage();
}

async function updateStats(delta = {}) {
  const current = await chrome.storage.local.get(["stats"]);
  const stats = current.stats || {
    scanned: 0,
    risky: 0,
    notifications: 0,
    lastRiskUrl: "",
  };

  const nextStats = {
    ...stats,
    scanned: stats.scanned + (delta.scanned || 0),
    risky: stats.risky + (delta.risky || 0),
    notifications: stats.notifications + (delta.notifications || 0),
    lastRiskUrl: delta.lastRiskUrl || stats.lastRiskUrl,
  };

  await chrome.storage.local.set({ stats: nextStats });
}

async function getCached(domain) {
  const stored = await chrome.storage.local.get(["domain_cache"]);
  const cache = stored.domain_cache || {};
  const entry = cache[domain];
  if (entry && Date.now() - entry.timestamp < 86400000) {
    return entry.result;
  }
  return null;
}

async function setCached(domain, result) {
  const stored = await chrome.storage.local.get(["domain_cache"]);
  const cache = stored.domain_cache || {};
  cache[domain] = { result, timestamp: Date.now() };
  await chrome.storage.local.set({ domain_cache: cache });
}

async function notifyIfRisky(result) {
  if (result.score < 60 || !result.url) return;
  if (sessionState.alertsSent.has(result.url)) return;

  sessionState.alertsSent.add(result.url);
  await chrome.notifications.create({
    type: "basic",
    iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAukB9Wyp7mQAAAAASUVORK5CYII=",
    title: "AegisNexus Shield",
    message: `Potential risk detected (${result.score}/100): ${result.host || result.url}`,
    priority: 2,
  });

  await updateStats({
    notifications: 1,
    lastRiskUrl: result.url,
  });
}

async function analyzeAndStore(urlString) {
  if (!urlString || !/^https?:/i.test(urlString)) return;
  const url = new URL(urlString);
  const bloomMatched = isBloomSuspicious(url.hostname);
  const host = (url.hostname || "").toLowerCase();
  const [dnsResult, gsbResult] = await Promise.all([checkDomainViaDNS(host), checkURL(urlString)]);
  const heuristic = analyzeURL(urlString, { bloomMatched, dnsResult, gsbResult });
  const result = {
    ...heuristic,
    url: urlString,
    host,
    https: url.protocol === "https:",
    dns: dnsResult,
    gsb: gsbResult,
  };

  await chrome.storage.local.set({
    lastScan: {
      ...result,
      scannedAt: Date.now(),
    },
  });

  await updateStats({
    scanned: 1,
    risky: result.score >= 60 ? 1 : 0,
    lastRiskUrl: result.score >= 60 ? result.url : "",
  });

  await notifyIfRisky(result);
}

chrome.runtime.onInstalled.addListener(async () => {
  // Periodic housekeeping to avoid unbounded notification cache.
  chrome.alarms.create("aegis-cache-cleanup", { periodInMinutes: 60 });
  await initializeBloomFilter();
  await chrome.storage.local.set({
    stats: {
      scanned: 0,
      risky: 0,
      notifications: 0,
      lastRiskUrl: "",
    },
  });
});

chrome.runtime.onStartup.addListener(() => {
  initializeBloomFilter().catch((error) => {
    console.warn("AegisNexus Shield: bloom filter init failed on startup", error);
  });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== "aegis-cache-cleanup") return;
  sessionState.alertsSent.clear();
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return; // Only top-level frame navigation.
  analyzeAndStore(details.url);
});

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    analyzeAndStore(details.url);
  },
  { urls: ["<all_urls>"] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_LAST_SCAN") {
    chrome.storage.local.get(["lastScan"]).then((data) => {
      sendResponse({ ok: true, lastScan: data.lastScan || null });
    });
    return true;
  }

  if (message?.type === "whitelist_add") {
    chrome.storage.local.get(["whitelist"]).then(async (stored) => {
      const list = Array.isArray(stored.whitelist) ? stored.whitelist : [];
      const domain = message.domain;
      if (domain && !list.some((e) => (typeof e === "string" ? e : e.domain) === domain)) {
        list.push({ domain, added_at: new Date().toISOString() });
        await chrome.storage.local.set({ whitelist: list });
      }
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "whitelist_remove") {
    chrome.storage.local.get(["whitelist"]).then(async (stored) => {
      let list = Array.isArray(stored.whitelist) ? stored.whitelist : [];
      const domain = message.domain;
      list = list.filter((e) => (typeof e === "string" ? e : e.domain) !== domain);
      await chrome.storage.local.set({ whitelist: list });
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "get_result") {
    const domain = message.domain || "";
    chrome.storage.local.get(["domain_cache", "whitelist"]).then((stored) => {
      const cache = stored.domain_cache || {};
      const whitelist = Array.isArray(stored.whitelist) ? stored.whitelist : [];
      const isWhitelisted = whitelist.some((e) => (typeof e === "string" ? e : e.domain) === domain);

      if (cache[domain] && Date.now() - cache[domain].timestamp < 86400000) {
        sendResponse({ ok: true, result: { ...cache[domain].result, whitelisted: isWhitelisted } });
      } else {
        chrome.storage.local.get(["lastScan"]).then((data) => {
          const last = data.lastScan || {};
          sendResponse({ ok: true, result: { ...last, whitelisted: isWhitelisted } });
        });
      }
    });
    return true;
  }

  if (message?.type === "force_scan") {
    const url = message.url || "";
    let parsed;
    try { parsed = new URL(url); } catch {
      sendResponse({ ok: false, error: "Invalid URL" });
      return false;
    }
    const host = (parsed.hostname || "").toLowerCase();
    Promise.all([checkDomainViaDNS(host), checkURL(url)])
      .then(([dnsResult, gsbResult]) => {
        const result = {
          ...analyzeURL(url, { bloomMatched: isBloomSuspicious(host), dnsResult, gsbResult }),
          url,
          host,
          https: parsed.protocol === "https:",
          dns: dnsResult,
          gsb: gsbResult,
          layer3: { requested: false },
        };
        setCached(host, result);
        sendResponse({ ok: true, result });
      })
      .catch(() => {
        const fallback = {
          ...analyzeURL(url, { bloomMatched: isBloomSuspicious(host) }),
          url,
          host,
          https: parsed.protocol === "https:",
          dns: { cloudflare_blocked: false, quad9_blocked: false, consensus_blocked: false, source: "dns" },
          gsb: { threat_found: false, threat_type: null, source: "gsb" },
          layer3: { requested: false },
        };
        sendResponse({ ok: true, result: fallback });
      });
    return true;
  }

  if (message?.type === "ANALYZE_URL") {
    const url = message.url || sender?.url || "";
    let parsed;
    try {
      parsed = new URL(url);
    } catch (error) {
      console.warn("AegisNexus Shield: URL parse failed in ANALYZE_URL", error);
      sendResponse({
        ok: true,
        result: {
          ...analyzeURL(url),
          url,
          host: "",
          https: false,
          dns: {
            cloudflare_blocked: false,
            quad9_blocked: false,
            consensus_blocked: false,
            source: "dns",
          },
          gsb: {
            threat_found: false,
            threat_type: null,
            source: "gsb",
          },
        },
      });
      return false;
    }

    const host = (parsed.hostname || "").toLowerCase();
    const https = parsed.protocol === "https:";
    Promise.all([checkDomainViaDNS(host), checkURL(url)])
      .then(([dnsResult, gsbResult]) => {
        const result = {
          ...analyzeURL(url, { bloomMatched: isBloomSuspicious(host), dnsResult, gsbResult }),
          url,
          host,
          https,
          dns: dnsResult,
          gsb: gsbResult,
        };
        sendResponse({ ok: true, result });
      })
      .catch((error) => {
        console.warn("AegisNexus Shield: external checks failed in ANALYZE_URL", error);
        const fallbackDns = {
          cloudflare_blocked: false,
          quad9_blocked: false,
          consensus_blocked: false,
          source: "dns",
        };
        const fallbackGsb = {
          threat_found: false,
          threat_type: null,
          source: "gsb",
        };
        const result = {
          ...analyzeURL(url, {
            bloomMatched: isBloomSuspicious(host),
            dnsResult: fallbackDns,
            gsbResult: fallbackGsb,
          }),
          url,
          host,
          https,
          dns: fallbackDns,
          gsb: fallbackGsb,
        };
        sendResponse({ ok: true, result });
      });
    return true;
  }

  return false;
});

initializeBloomFilter().catch((error) => {
  console.warn("AegisNexus Shield: bloom filter init failed", error);
});
