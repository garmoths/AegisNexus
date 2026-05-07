const FLAG_POINTS = {
  "ip-address-host": 25,
  "suspicious-tld": 20,
  "long-url": 15,
  "at-symbol": 20,
  "too-many-subdomains": 15,
  "brand-subdomain-spoof": 30,
  "hex-encoding": 10,
  "double-encoding": 20,
  "homograph-characters": 25,
  "http-sensitive-keyword": 20,
  "suspicious-keywords": 20,
  "non-standard-port": 15,
  "too-many-dots": 10,
  "bloom-suspect-domain": 20,
  "dns-consensus-blocked": 40,
  "dns-provider-blocked": 20,
  "gsb-threat": 50,
};

const FLAG_ICONS = {
  "ip-address-host": "🧭",
  "suspicious-tld": "🌐",
  "long-url": "📏",
  "at-symbol": "@",
  "too-many-subdomains": "🧩",
  "brand-subdomain-spoof": "🎭",
  "hex-encoding": "🧪",
  "double-encoding": "🧪",
  "homograph-characters": "🔤",
  "http-sensitive-keyword": "🔓",
  "suspicious-keywords": "🚩",
  "non-standard-port": "🔌",
  "too-many-dots": "…",
  "bloom-suspect-domain": "🧫",
  "dns-consensus-blocked": "🌐",
  "dns-provider-blocked": "🌐",
  "gsb-threat": "🛡️",
};

const RISK_BADGE_EMOJI = {
  "KRİTİK": "🔴",
  "YÜKSEK": "🟠",
  "ORTA": "🟡",
  "DÜŞÜK": "🟢",
  "GÜVENLİ": "✅",
  "CRITICAL": "🔴",
  "HIGH": "🟠",
  "MEDIUM": "🟡",
  "LOW": "🟢",
  "SAFE": "✅",
};
const DB_STATS_CACHE_KEY = "db_stats_summary_cache";
const DB_STATS_CACHE_TTL_MS = 60 * 60 * 1000;

const state = {
  tab: null,
  domain: "",
  url: "",
  result: null,
};

function byId(id) {
  return document.getElementById(id);
}

function showPopupMessage(message, tone = "info") {
  let box = byId("popup-message");
  if (!box) {
    box = document.createElement("div");
    box.id = "popup-message";
    box.style.marginTop = "8px";
    box.style.padding = "8px 10px";
    box.style.borderRadius = "8px";
    box.style.fontSize = "12px";
    box.style.fontWeight = "700";
    box.style.transition = "opacity .2s ease";
    const section = document.querySelector(".button-grid");
    section?.insertAdjacentElement("afterend", box);
  }

  box.style.opacity = "1";
  box.style.color = "#e2e8f0";
  box.style.background = tone === "error" ? "#7f1d1d" : tone === "success" ? "#14532d" : "#0f3a54";
  box.textContent = message;

  setTimeout(() => {
    box.style.opacity = "0";
  }, 2600);
}

function clampScore(value) {
  const n = Number(value || 0);
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

function getSafetyLabel(score) {
  const safeScore = clampScore(score);
  // Yeni skor bandları: 0-20 kritik, 20-40 riskli, 40-60 orta, 60-80 iyi, 80-100 güvenilir
  if (safeScore >= 80) return "GÜVENLİ";
  if (safeScore >= 60) return "İYİ";
  if (safeScore >= 40) return "ORTA";
  if (safeScore >= 20) return "RİSKLİ";
  return "KRİTİK";
}

function badgeClass(score) {
  const safeScore = clampScore(score);
  // Renkler: KRİTİK=kırmızı, RİSKLİ=turuncu, ORTA=sarı, İYİ=yeşil açık, GÜVENLİ=yeşil
  if (safeScore >= 80) return "risk-safe";
  if (safeScore >= 60) return "risk-good";
  if (safeScore >= 40) return "risk-medium";
  if (safeScore >= 20) return "risk-high";
  return "risk-critical";
}

function setRiskCircle(score) {
  const ring = byId("risk-ring");
  const scoreValue = byId("score-value");
  const target = clampScore(score);
  const duration = 500;
  const start = performance.now();

  function riskColor(val) {
    // 0-20: kırmızı (kritik), 20-40: turuncu (riskli), 40-60: sarı (orta), 60-80: açık yeşil (iyi), 80-100: yeşil (güvenilir)
    if (val <= 20) return "#ef4444";     // KRİTİK - Kırmızı
    if (val <= 40) return "#ff6b35";     // RİSKLİ - Turuncu
    if (val <= 60) return "#f59e0b";     // ORTA - Sarı
    if (val <= 80) return "#84cc16";     // İYİ - Açık Yeşil (Lime)
    return "#22c55e";                     // GÜVENLİ - Yeşil
  }

  function frame(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    const current = Math.round(target * eased);
    const deg = current * 3.6;
    const color = riskColor(current);
    ring.style.setProperty("--fill-color", color);
    ring.style.background = `conic-gradient(${color} ${deg}deg, #0d1929 0deg)`;
    scoreValue.textContent = String(current);
    if (t < 1) requestAnimationFrame(frame);
  }

  ring.style.setProperty("--fill-color", "#22c55e");
  ring.style.background = "conic-gradient(#22c55e 0deg, #0d1929 0deg)";
  scoreValue.textContent = "0";
  requestAnimationFrame(frame);
}

function renderHeuristic(result) {
  const flags = Array.isArray(result?.flags) ? result.flags : [];
  const list = byId("heuristic-flags");
  const breakdown = byId("heuristic-score-breakdown");
  const analysisSource = String(result?.source || "").toLowerCase();
  const analysisTitle = analysisSource.startsWith("server") ? "Sunucu Analizi" : "Yerel Analiz";

  breakdown.textContent = `${analysisTitle} | Güvenilirlik skoru: ${clampScore(result?.score)}/100 | Seviye: ${result?.risk_level || "GÜVENLİ"}`;

  if (flags.length === 0) {
    list.innerHTML = "<li>Şüpheli flag yok</li>";
    return;
  }

  list.innerHTML = flags
    .map((flag) => {
      const icon = FLAG_ICONS[flag] || "•";
      const points = FLAG_POINTS[flag] || 0;
      return `<li>${icon} ${flag} ${points > 0 ? `(+${points})` : ""}</li>`;
    })
    .join("");
}

function renderDns(result) {
  const dns = result?.dns || {};
  const dnsSourceRaw = String(dns.source || "").toLowerCase();
  const dnsSourceLabel = dnsSourceRaw.includes("server") || dnsSourceRaw.includes("external")
    ? "Sunucu DNS"
    : dnsSourceRaw
      ? dns.source
      : "Bilinmeyen DNS";
  byId("dns-cloudflare").textContent = dns.cloudflare_blocked ? "❌ Blocked" : "✅ Clean";
  byId("dns-quad9").textContent = dns.quad9_blocked ? "❌ Blocked" : "✅ Clean";
  byId("dns-consensus").textContent = `${dns.consensus_blocked ? "❌ Blocked" : "✅ Clear"} • ${dnsSourceLabel}`;
}

function renderGsb(result) {
  const gsb = result?.gsb || {};
  if (!gsb.available) {
    byId("gsb-status").textContent = "Kullanılamıyor";
    byId("gsb-type").textContent = "-";
    return;
  }
  byId("gsb-status").textContent = gsb.threat_found ? "Threat bulundu" : "Temiz";
  byId("gsb-type").textContent = gsb.threat_type || "-";
}

function ensureLayer3Bar() {
  let bar = byId("layer3-progress");
  if (bar) return bar;

  const statusNode = byId("layer3-status");
  const content = statusNode.closest(".accordion-content");
  if (!content) return null;

  const wrapper = document.createElement("div");
  wrapper.style.marginTop = "8px";
  wrapper.innerHTML =
    '<div style="height:8px;background:#1e293b;border-radius:999px;overflow:hidden;"><div id="layer3-progress" style="height:100%;width:0%;background:#38bdf8;transition:width .25s ease;"></div></div>';
  content.appendChild(wrapper);
  return byId("layer3-progress");
}

function renderLayer3(result) {
  const layer3 = result?.layer3 || { requested: false };
  const layer3Payload = layer3?.data && typeof layer3.data === "object"
    ? (layer3.data?.data && typeof layer3.data.data === "object" ? layer3.data.data : layer3.data)
    : {};
  const confidenceEl = byId("layer3-confidence");
  const statusEl = byId("layer3-status");
  const progress = ensureLayer3Bar();

  if (!layer3.requested) {
    statusEl.textContent = "Atlanmış";
    confidenceEl.textContent = "-";
    if (progress) progress.style.width = "0%";
    return;
  }

  const layer3Source = String(layer3Payload?.source || result?.source || "").toLowerCase();
  const sourceLabel = layer3Source.startsWith("server") ? "Sunucu" : "Katman 3";
  statusEl.textContent = layer3.ok
    ? `${sourceLabel} (${Number(layer3.status) || 200})`
    : `Hata (${Number(layer3.status) || "-"})`;
  const confidence =
    Number(
      layer3Payload?.confidence_score
      ?? layer3Payload?.confidence
      ?? layer3Payload?.score
      ?? result?.score
      ?? (layer3.ok ? 70 : 20)
    ) || 0;
  const safe = clampScore(confidence);
  confidenceEl.textContent = `${safe}%`;
  if (progress) progress.style.width = `${safe}%`;
}

async function sendNotification(score, domain) {
  // Skor 60'nin altında ise (RİSKLİ ve KRİTİK) bildirim gönder
  if (score >= 60) return;
  
  // Notification permission talep et
  try {
    if (Notification.permission === 'denied') {
      console.warn("Notifications are disabled");
      return;
    }
    
    if (Notification.permission === 'default') {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') return;
    }
  } catch (err) {
    console.warn("Notification permission error:", err);
  }
  
  const safeScore = clampScore(score);
  let title = "⚠️ Güvenlik Uyarısı";
  let message = `${domain} — Güvenilirlik: ${safeScore}/100`;
  let priority = 1;
  
  // Yeni skor bandlarına göre bildirim seviyesi
  if (safeScore < 20) {
    title = "🔴 KRİTİK UYARI";
    message = `KRİTİK SEVIYE RİSK TESPIT EDİLDİ: ${domain} — Güvenilirlik: ${safeScore}/100`;
    priority = 2;
  } else if (safeScore < 40) {
    title = "🟠 RİSKLİ UYARI";
    message = `RİSKLİ: ${domain} — Güvenilirlik: ${safeScore}/100`;
    priority = 2;
  } else if (safeScore < 60) {
    title = "🟡 ORTA RİSK";
    message = `ORTA RİSK: ${domain} — Güvenilirlik: ${safeScore}/100`;
    priority = 1;
  } else if (safeScore < 70) {
    title = "🟢 İYİ (SINIRLAYAN)";
    message = `İYİ (sınır): ${domain} — Güvenilirlik: ${safeScore}/100`;
    priority = 0;
  }
  
  try {
    // Chrome Notifications API
    if (chrome?.notifications) {
      await chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon128.png"),
        title: title,
        message: message,
        priority: priority,
      });
    } else {
      // Fallback: Web Notification API (Manifest V3 popup'ta)
      new Notification(title, {
        body: message,
        icon: chrome.runtime.getURL("icons/icon128.png"),
      });
    }
  } catch (err) {
    console.warn("Notification error:", err);
  }
}

function renderResult(result) {
  state.result = result || {};
  const score = clampScore(result?.score);
  const risk = String(getSafetyLabel(score)).toUpperCase();

  // Skor 70'nin altında bildirim gönder
  if (score < 70) {
    sendNotification(score, state.domain).catch(console.warn);
  }

  setRiskCircle(score);

  const badge = byId("risk-badge");
  badge.className = `risk-badge ${badgeClass(score)}`;
  badge.textContent = risk;

  renderHeuristic(result);
  renderDns(result);
  renderGsb(result);
  renderLayer3(result);
  renderDbRecord(result);

  const sourceEl = byId("deep-scan-source");
  if (sourceEl) {
    const src = result?.deep_scan_source;
    const srcMap = { cache: "✅ Cache", db: "🗄️ Veritabanı", api: "🔎 API", api_celery: "🔎 Derin API", api_celery_timeout: "⚠️ Zaman Aşımı" };
    const srcLabel = result?.source === "server" ? "🌐 Sunucu" : result?.source === "local" ? "💻 Yerel Analiz" : "💻 Yerel Analiz";
    sourceEl.textContent = srcMap[src] || srcLabel;
  }
}

function renderDbRecord(result) {
  const match = result?.db_match;
  byId("db-match-status").textContent = match ? "✅ Kayıtlı" : "❌ Kayıt yok";
  if (!match) {
    byId("db-risk-score").textContent = "-";
    byId("db-risk-level").textContent = "-";
    byId("db-is-safe").textContent = "-";
    byId("db-last-updated").textContent = "-";
    return;
  }
  const dbSafetyScore = clampScore(result.db_risk_score);
  byId("db-risk-score").textContent = String(dbSafetyScore);
  byId("db-risk-level").textContent = result.db_risk_level || "-";
  byId("db-is-safe").textContent = result.db_is_safe ? "✅ Evet" : "❌ Hayır";
  byId("db-last-updated").textContent = result.db_last_updated || "-";
}

function renderFormList(targetId, values) {
  const node = byId(targetId);
  const safeValues = Array.isArray(values) ? [...new Set(values.filter(Boolean))] : [];
  if (safeValues.length === 0) {
    node.innerHTML = "<li>Henüz veri yok</li>";
    return;
  }
  node.innerHTML = safeValues.map((item) => `<li>${item}</li>`).join("");
}

function renderFormDetection(formScan) {
  const data = formScan || {};
  byId("form-count").textContent = String(Number(data.form_count || 0));
  byId("form-highest-score").textContent = String(Number(data.highest_risk_score || 0));
  byId("form-risk-level").textContent = String(data.combined_risk_level || data.risk_level || "SAFE").toUpperCase();

  renderFormList("form-flags", data.flags || []);
  renderFormList("form-field-types", data.field_types || data.suspicious_forms?.flatMap((form) => form.field_types || []));
}

function riskBadgeHtml(riskLevel) {
  const level = String(riskLevel || "safe").toUpperCase();
  const colors = { SAFE: "#22c55e", LOW: "#3b82f6", MEDIUM: "#eab308", HIGH: "#f97316", CRITICAL: "#ef4444" };
  const color = colors[level] || "#6b7280";
  return `<span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;background:${color};color:#fff;">${level}</span>`;
}

function renderAnalysisHistory(data) {
  const list = byId("analysis-history");
  const results = Array.isArray(data?.results) ? data.results : [];
  const btnMore = byId("btn-load-more-history");

  if (results.length === 0) {
    list.innerHTML = "<li>Bu domain için geçmiş tarama yok</li>";
    if (btnMore) btnMore.style.display = "none";
    return;
  }

  list.innerHTML = results.map((item) => {
    const date = item.created_at ? new Date(item.created_at).toLocaleString("tr-TR", { dateStyle: "short", timeStyle: "short" }) : "-";
    const shortUrl = (item.url || "").length > 40 ? item.url.slice(0, 40) + "…" : item.url;
    return `<li>${riskBadgeHtml(item.risk_level)} ${shortUrl} — ${date}</li>`;
  }).join("");

  if (btnMore && data.count > results.length) {
    btnMore.style.display = "inline-block";
  } else if (btnMore) {
    btnMore.style.display = "none";
  }
}

async function loadAnalysisHistory(limit = 5) {
  if (!state.domain) return;
  const stored = await chrome.storage.local.get(["api_base_url"]);
  const base = String(stored.api_base_url || "http://127.0.0.1:8000").trim().replace(/\/+$/g, "");
  try {
    const response = await fetch(`${base}/api/v2/phishing/analysis-history?domain=${encodeURIComponent(state.domain)}&limit=${limit}`);
    if (!response.ok) return;
    const data = await response.json();
    renderAnalysisHistory(data);
  } catch {
    byId("analysis-history").innerHTML = "<li>Sunucuya ulaşılamadı</li>";
  }
}

function renderDbStats(data) {
  if (!data) return;
  byId("stat-phishing-count").textContent = String(data.phishing_url_count ?? "-");
  byId("stat-phishing-online").textContent = String(data.phishing_url_online_count ?? "-");
  byId("stat-whitelist-count").textContent = String(data.whitelist_domain_count ?? "-");
  byId("stat-ioc-count").textContent = String(data.ioc_active_count ?? "-");
  byId("stat-form-pending").textContent = String(data.form_pending_review_count ?? "-");
  byId("stat-last-updated").textContent = data.last_updated ? new Date(data.last_updated).toLocaleString("tr-TR", { dateStyle: "short", timeStyle: "short" }) : "-";

  const byType = data.ioc_by_type || {};
  const typeList = byId("stat-ioc-by-type");
  const entries = Object.entries(byType);
  if (entries.length === 0) {
    typeList.innerHTML = "";
  } else {
    typeList.innerHTML = entries.map(([type, count]) => `<li>${type}: ${count}</li>`).join("");
  }
}

async function loadDbStats() {
  const STATS_CACHE_KEY = "db_stats_cache";
  const STATS_CACHE_TTL = 3600000; // 1 hour

  const cached = await chrome.storage.local.get([STATS_CACHE_KEY]);
  if (cached[STATS_CACHE_KEY]) {
    const entry = cached[STATS_CACHE_KEY];
    if (Date.now() - Number(entry.cachedAt || 0) < STATS_CACHE_TTL) {
      renderDbStats(entry.data);
      return;
    }
  }

  const stored = await chrome.storage.local.get(["api_base_url"]);
  const base = String(stored.api_base_url || "http://127.0.0.1:8000").trim().replace(/\/+$/g, "");
  try {
    const response = await fetch(`${base}/api/v2/phishing/stats-summary`);
    if (!response.ok) return;
    const data = await response.json();
    renderDbStats(data);
    await chrome.storage.local.set({ [STATS_CACHE_KEY]: { cachedAt: Date.now(), data } });
  } catch {}
}

async function sendRuntimeMessage(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "Runtime message failed");
  return response.result;
}

function setDeepScanLoading(loading) {
  const button = byId("btn-deep-scan");
  if (!button) return;
  if (loading) {
    button.disabled = true;
    button.dataset.originalText = button.textContent;
    button.textContent = "⏳ Taranıyor...";
  } else {
    button.disabled = false;
    button.textContent = button.dataset.originalText || "🔎 Derin Tara";
  }
}

function setDeepScanProgress(text) {
  const button = byId("btn-deep-scan");
  if (button && text) button.textContent = text;
}

function setSourceLabel(src) {
  const sourceEl = byId("deep-scan-source");
  if (!sourceEl) return;
  const sourceMap = {
    cache:              "✅ Cache",
    db:                 "🗄️ Veritabanı",
    api:                "🔎 API",
    api_celery:         "🔎 Derin API",
    api_celery_timeout: "⚠️ Zaman Aşımı",
    local:              "💻 Yerel Analiz",
  };
  sourceEl.textContent = sourceMap[src] || src || "—";
}

async function deepScanFetch(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 10000);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timeout);
  }
}

async function pollJobResult(base, jobId, onProgress) {
  const MAX_POLLS = 90;
  const INTERVAL = 3000;
  for (let i = 0; i < MAX_POLLS; i++) {
    await new Promise((r) => setTimeout(r, INTERVAL));
    try {
      const res = await deepScanFetch(`${base}/api/v2/phishing/result/${jobId}`, { timeoutMs: 8000 });
      if (!res.ok) continue;
      const data = await res.json();
      if (data.status === "done" || data.status === "completed") return { done: true, data };
      const pct = data.progress ?? Math.round((i / MAX_POLLS) * 100);
      onProgress(`⏳ Derin analiz: %${pct}`);
    } catch { /* devam et */ }
  }
  return { done: false, data: null };
}

async function runDeepScan() {
  if (!state.domain || !state.url) return;
  setDeepScanLoading(true);
  const base = await getApiBaseUrl();

  try {
    // Adım 1 — DB Lookup (<5ms)
    setDeepScanProgress("🗄️ Veritabanı kontrol ediliyor...");
    try {
      const dbRes = await deepScanFetch(
        `${base}/api/v2/phishing/db-lookup?url=${encodeURIComponent(state.url)}`,
        { timeoutMs: 5000 }
      );
      if (dbRes.ok) {
        const dbData = await dbRes.json();
        if (dbData.found === true) {
          const safetyScore = clampScore(dbData.risk_score);
          const riskLevel = String(dbData.risk_level || "GÜVENLİ");
          const result = {
            score: safetyScore,
            risk_level: riskLevel,
            is_phishing: safetyScore < 40,
            is_safe: Boolean(dbData.is_safe),
            flags: [],
            sources: Array.isArray(dbData.sources) ? dbData.sources : [],
            source: "db",
            deep_scan_source: "db",
            domain: state.domain,
            url: state.url,
          };
          renderResult(result);
          setSourceLabel("db");
          showPopupMessage(`🗄️ Veritabanı — Güvenilirlik: ${safetyScore}/100`, safetyScore < 40 ? "error" : "success");
          return;
        }
      }
    } catch { /* DB erişilemez, devam et */ }

    // Adım 2 — POST /check-url
    setDeepScanProgress("🔎 Sunucuya gönderiliyor...");
    let checkRes;
    try {
      checkRes = await deepScanFetch(`${base}/api/v2/phishing/check-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: state.url }),
        timeoutMs: 15000,
      });
    } catch {
      showPopupMessage("⚠️ Sunucuya ulaşılamadı — yerel analiz gösteriliyor", "error");
      setSourceLabel("local");
      return;
    }

    if (!checkRes.ok) {
      showPopupMessage(`Sunucu hatası: ${checkRes.status}`, "error");
      setSourceLabel("local");
      return;
    }

    const checkData = await checkRes.json();

    // Adım 3 — Celery polling (status: analyzing)
    if (checkData.status === "analyzing" && checkData.job_id) {
      setDeepScanProgress("⏳ Derin analiz başlatıldı...");
      const poll = await pollJobResult(base, checkData.job_id, setDeepScanProgress);

      if (!poll.done) {
        showPopupMessage("⚠️ Analiz zaman aşımına uğradı — lokal sonuç gösteriliyor", "error");
        setSourceLabel("api_celery_timeout");
        return;
      }

      const finalData = poll.data?.data ?? poll.data;
      const safetyScore = clampScore(finalData?.score);
      const riskLevel = String(finalData?.risk_level || "GÜVENLİ");
      const result = {
        ...finalData,
        score: safetyScore,
        risk_level: riskLevel,
        is_phishing: safetyScore < 40,
        deep_scan_source: "api_celery",
        source: "server",
        domain: state.domain,
        url: state.url,
      };
      renderResult(result);
      setSourceLabel("api_celery");
      showPopupMessage(`🔎 Derin Analiz Tamamlandı — Güvenilirlik: ${safetyScore}/100`, safetyScore < 40 ? "error" : "success");
      return;
    }

    // Adım 4 — Direkt sonuç (hızlı yanıt)
    const rawScore = checkData?.score ?? checkData?.data?.score ?? 0;
    const safetyScore = clampScore(rawScore);
    const riskLevel = String(checkData?.risk_level ?? checkData?.data?.risk_level ?? "GÜVENLİ");
    const result = {
      ...(checkData?.data ?? checkData),
      score: safetyScore,
      risk_level: riskLevel,
      is_phishing: safetyScore < 40,
      deep_scan_source: "api",
      source: "server",
      domain: state.domain,
      url: state.url,
    };
    renderResult(result);
    setSourceLabel("api");
    showPopupMessage(`🔎 API Analizi — Güvenilirlik: ${safetyScore}/100`, safetyScore < 40 ? "error" : "success");

  } catch (err) {
    showPopupMessage(`Derin tarama hatası: ${err.message}`, "error");
  } finally {
    setDeepScanLoading(false);
  }
}

async function addToWhitelist() {
  if (!state.domain) return;
  const button = byId("btn-trust");
  const stored = await chrome.storage.local.get(["whitelist"]);
  const list = Array.isArray(stored.whitelist) ? stored.whitelist : [];
  const next = [...new Set([...list, state.domain])];
  await chrome.storage.local.set({ whitelist: next });
  await chrome.runtime.sendMessage({ type: "whitelist_add", domain: state.domain });
  button.textContent = "✅ Güvenilir";
  button.disabled = true;
}

async function reportDomain() {
  if (!state.domain || !state.url) return;
  const button = byId("btn-report");
  const base = await getApiBaseUrl();
  const response = await fetch(`${base}/api/v2/phishing/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: state.url,
      reported_by: "extension",
      reason: "phishing",
    }),
  });
  if (response.status === 429) {
    showPopupMessage("Çok fazla rapor gönderdiniz, lütfen bekleyin", "error");
    return;
  }
  if (!response.ok) throw new Error("Report failed");
  button.textContent = "🚨 Raporlandı";
  button.disabled = true;
  showPopupMessage("Rapor alındı", "success");
}

function showSavedFeedback() {
  const button = byId("btn-save-settings");
  const original = button.textContent;
  button.textContent = "✅ Kaydedildi!";
  button.style.transform = "scale(1.02)";
  setTimeout(() => {
    button.textContent = original;
    button.style.transform = "";
  }, 1200);
}

async function saveSettings() {
  const apiBaseUrl = byId("api-base-url").value.trim();
  const gsbApiKey = byId("gsb-api-key").value.trim();
  await chrome.storage.local.set({
    api_base_url: apiBaseUrl,
    gsb_api_key: gsbApiKey,
  });
  showSavedFeedback();
}

function bindSettingsToggle() {
  const keyInput = byId("gsb-api-key");
  const button = byId("toggle-gsb-key");
  button.addEventListener("click", () => {
    const show = keyInput.type === "password";
    keyInput.type = show ? "text" : "password";
    button.textContent = show ? "Gizle" : "Göster";
  });
}

async function loadStoredSettings() {
  const stored = await chrome.storage.local.get(["api_base_url", "gsb_api_key", "whitelist"]);
  byId("api-base-url").value = String(stored.api_base_url || "");
  byId("gsb-api-key").value = String(stored.gsb_api_key || "");

  const whitelist = Array.isArray(stored.whitelist) ? stored.whitelist : [];
  if (whitelist.includes(state.domain)) {
    const button = byId("btn-trust");
    button.textContent = "✅ Güvenilir";
    button.disabled = true;
  }
}

async function getApiBaseUrl() {
  const stored = await chrome.storage.local.get(["api_base_url"]);
  return String(stored.api_base_url || "http://127.0.0.1:8000").trim().replace(/\/+$/g, "");
}



async function initActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  state.tab = tab || null;
  state.url = String(tab?.url || "");

  let domain = "";
  try {
    domain = new URL(state.url).hostname;
  } catch {}
  state.domain = domain;
  byId("active-domain").textContent = domain || "domain.yok";
}

async function loadResult() {
  if (!state.domain || !state.url) return;
  const result = await sendRuntimeMessage({ type: "get_result", domain: state.domain, url: state.url });
  renderResult(result);

  const stored = await chrome.storage.local.get(["lastFormScan"]);
  let formScan = stored.lastFormScan || null;

  if (state.tab?.id) {
    try {
      const pageSignals = await chrome.tabs.sendMessage(state.tab.id, { type: "GET_PAGE_SIGNALS" });
      if (pageSignals?.ok && pageSignals.pageSignals?.form_scan) {
        formScan = pageSignals.pageSignals.form_scan;
      }
    } catch {}
  }

  renderFormDetection(formScan);
  loadAnalysisHistory(5);
}

function bindActions() {
  byId("btn-deep-scan").addEventListener("click", () => {
    runDeepScan().catch((error) => console.warn("AegisNexus Shield: deep scan failed", error));
  });
  byId("btn-trust").addEventListener("click", () => {
    addToWhitelist().catch((error) => console.warn("AegisNexus Shield: whitelist failed", error));
  });
  byId("btn-report").addEventListener("click", () => {
    reportDomain().catch((error) => {
      console.warn("AegisNexus Shield: report failed", error);
      showPopupMessage("Rapor gönderilemedi", "error");
    });
  });
  byId("btn-save-settings").addEventListener("click", () => {
    saveSettings().catch((error) => console.warn("AegisNexus Shield: save settings failed", error));
  });
  byId("btn-load-more-history").addEventListener("click", () => {
    loadAnalysisHistory(20).catch((error) => console.warn("AegisNexus Shield: load more history failed", error));
  });
}

async function init() {
  bindActions();
  bindSettingsToggle();
  await initActiveTab();
  await loadStoredSettings();
  await loadResult();
  await loadDbStats();
}

init().catch((error) => {
  console.warn("AegisNexus Shield: popup init failed", error);
});
