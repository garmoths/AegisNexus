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

function badgeClass(riskLevel) {
  const level = String(riskLevel || "SAFE").toUpperCase();
  if (level === "CRITICAL") return "risk-critical";
  if (level === "HIGH") return "risk-high";
  if (level === "MEDIUM") return "risk-medium";
  if (level === "LOW") return "risk-low";
  return "risk-safe";
}

function setRiskCircle(score) {
  const ring = byId("risk-ring");
  const scoreValue = byId("score-value");
  const target = clampScore(score);
  const duration = 500;
  const start = performance.now();

  function frame(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    const current = Math.round(target * eased);
    const deg = current * 3.6;
    ring.style.background = `conic-gradient(#38bdf8 ${deg}deg, #1e293b 0deg)`;
    scoreValue.textContent = String(current);
    if (t < 1) requestAnimationFrame(frame);
  }

  ring.style.background = "conic-gradient(#38bdf8 0deg, #1e293b 0deg)";
  scoreValue.textContent = "0";
  requestAnimationFrame(frame);
}

function renderHeuristic(result) {
  const flags = Array.isArray(result?.flags) ? result.flags : [];
  const list = byId("heuristic-flags");
  const breakdown = byId("heuristic-score-breakdown");

  breakdown.textContent = `Toplam skor: ${clampScore(result?.score)} | Risk: ${result?.risk_level || "SAFE"}`;

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
  byId("dns-cloudflare").textContent = dns.cloudflare_blocked ? "❌ Blocked" : "✅ Clean";
  byId("dns-quad9").textContent = dns.quad9_blocked ? "❌ Blocked" : "✅ Clean";
  byId("dns-consensus").textContent = dns.consensus_blocked ? "❌ Blocked" : "✅ Clear";
}

function renderGsb(result) {
  const gsb = result?.gsb || {};
  if (gsb.skipped) {
    byId("gsb-status").textContent = "API Key girilmedi";
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
  const confidenceEl = byId("layer3-confidence");
  const statusEl = byId("layer3-status");
  const progress = ensureLayer3Bar();

  if (!layer3.requested) {
    statusEl.textContent = "Atlanmış";
    confidenceEl.textContent = "-";
    if (progress) progress.style.width = "0%";
    return;
  }

  statusEl.textContent = layer3.ok ? "Tamamlandı" : "Hata";
  const confidence =
    Number(layer3?.data?.confidence_score ?? layer3?.data?.confidence ?? (layer3.ok ? 70 : 20)) || 0;
  const safe = clampScore(confidence);
  confidenceEl.textContent = `${safe}%`;
  if (progress) progress.style.width = `${safe}%`;
}

function renderResult(result) {
  state.result = result || {};
  const score = clampScore(result?.score);
  const risk = String(result?.risk_level || "SAFE").toUpperCase();

  setRiskCircle(score);

  const badge = byId("risk-badge");
  badge.className = `risk-badge ${badgeClass(risk)}`;
  badge.textContent = risk;

  renderHeuristic(result);
  renderDns(result);
  renderGsb(result);
  renderLayer3(result);
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

async function runDeepScan() {
  if (!state.domain || !state.url) return;
  setDeepScanLoading(true);
  try {
    const result = await sendRuntimeMessage({ type: "force_scan", domain: state.domain, url: state.url });
    renderResult(result);
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
  const stored = await chrome.storage.local.get(["api_base_url"]);
  const base = String(stored.api_base_url || "http://127.0.0.1:8000").trim().replace(/\/+$/g, "");
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
}

async function init() {
  bindActions();
  bindSettingsToggle();
  await initActiveTab();
  await loadStoredSettings();
  await loadResult();
}

init().catch((error) => {
  console.warn("AegisNexus Shield: popup init failed", error);
});
