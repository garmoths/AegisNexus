const BANNER_HOST_ID = "aegisnexus-shield-warning-host";
const FORM_WARNING_CLASS = "aegisnexus-form-warning";
const FORM_HIGHLIGHT_CLASS = "aegisnexus-form-highlight";

const formDetectorPromise = import(chrome.runtime.getURL("utils/form_detector.js"));
const fieldClassifierPromise = import(chrome.runtime.getURL("utils/field_classifier.js"));

let lastFormScanResult = null;

function getBannerColor(riskLevel) {
  const lvl = String(riskLevel || "").toLowerCase();
  if (lvl === "kri̇ti̇k" || lvl === "kritik" || lvl === "critical") return "#ef4444";
  if (lvl === "yüksek" || lvl === "yuksek" || lvl === "high") return "#f97316";
  if (lvl === "orta" || lvl === "medium") return "#eab308";
  return "#eab308";
}

function buildFlagsText(flags) {
  if (!Array.isArray(flags) || flags.length === 0) return "Flags: none";
  return `Flags: ${flags.slice(0, 5).join(", ")}`;
}

async function isDismissed(domain) {
  const key = `dismissed:${domain}`;
  const data = await chrome.storage.local.get([key]);
  return data[key] === true;
}

async function markDismissed(domain) {
  const key = `dismissed:${domain}`;
  await chrome.storage.local.set({ [key]: true });
}

function removeBanner() {
  const existing = document.getElementById(BANNER_HOST_ID);
  if (existing) existing.remove();
}

function ensureMountPoint() {
  return document.body || document.documentElement;
}

function renderBanner({ risk_level, score, flags }, domain) {
  removeBanner();
  const mount = ensureMountPoint();
  if (!mount) return;

  const host = document.createElement("div");
  host.id = BANNER_HOST_ID;
  mount.appendChild(host);

  const shadow = host.attachShadow({ mode: "closed" });
  const background = getBannerColor(String(risk_level || "ORTA"));
  const safeScore = Number(score || 0);
  const safeRisk = String(risk_level || "ORTA");

  const wrapper = document.createElement("div");
  wrapper.innerHTML = `
    <style>
      .aegis-banner {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        z-index: 2147483647;
        background: ${background};
        color: #ffffff;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, Arial, sans-serif;
        font-weight: 700;
        padding: 12px 14px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35);
        box-sizing: border-box;
      }
      .aegis-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        flex-wrap: wrap;
      }
      .aegis-message {
        font-size: 14px;
      }
      .aegis-flags {
        margin-top: 6px;
        font-size: 12px;
        opacity: 0.95;
      }
      .aegis-actions {
        display: flex;
        gap: 8px;
      }
      .aegis-btn {
        appearance: none;
        border: 1px solid rgba(255, 255, 255, 0.7);
        border-radius: 8px;
        padding: 7px 10px;
        font-size: 12px;
        font-weight: 700;
        cursor: pointer;
        color: #ffffff;
        background: rgba(0, 0, 0, 0.16);
      }
      .aegis-btn:hover {
        background: rgba(0, 0, 0, 0.26);
      }
    </style>
    <div class="aegis-banner">
      <div class="aegis-row">
        <div class="aegis-message">⚠️ Bu site tehlikeli olabilir! Risk: ${safeRisk} | Risk Skoru: ${safeScore}/100</div>
        <div class="aegis-actions">
          <button class="aegis-btn" id="aegis-continue">Yine de Devam Et</button>
          <button class="aegis-btn" id="aegis-back">Geri Dön</button>
        </div>
      </div>
      <div class="aegis-flags">${buildFlagsText(flags)}</div>
    </div>
  `;

  shadow.appendChild(wrapper);

  wrapper.querySelector("#aegis-continue")?.addEventListener("click", () => {
    markDismissed(domain)
      .catch(() => {})
      .finally(() => removeBanner());
  });

  wrapper.querySelector("#aegis-back")?.addEventListener("click", () => {
    history.back();
  });
}

function clearFormWarnings() {
  document.querySelectorAll(`.${FORM_WARNING_CLASS}`).forEach((n) => n.remove());
  document.querySelectorAll(`.${FORM_HIGHLIGHT_CLASS}`).forEach((n) => n.classList.remove(FORM_HIGHLIGHT_CLASS));
}

function injectFormWarning(form, suspicious) {
  if (!form) return;
  if (form.previousElementSibling?.classList?.contains(FORM_WARNING_CLASS)) return;

  const banner = document.createElement("div");
  banner.className = FORM_WARNING_CLASS;
  banner.style.cssText = [
    "background:#7f1d1d",
    "color:#fff",
    "padding:6px 10px",
    "font-size:12px",
    "font-family:Arial,sans-serif",
    "font-weight:700",
    "border-radius:6px",
    "margin-bottom:6px",
  ].join(";");
  banner.textContent = `⚠️ Şüpheli form tespit edildi! Risk: ${suspicious.risk_level} | ${suspicious.flags.slice(0, 3).join(", ")}`;
  form.parentNode?.insertBefore(banner, form);
}

function highlightForm(form) {
  if (!form) return;
  form.classList.add(FORM_HIGHLIGHT_CLASS);
  form.style.outline = "2px solid #dc2626";
  form.style.outlineOffset = "2px";
}

function showFormWarnings(targetFormIndices = null) {
  if (!lastFormScanResult) return;

  const forms = document.querySelectorAll("form");
  const indexFilter = Array.isArray(targetFormIndices) ? new Set(targetFormIndices) : null;

  for (const suspicious of lastFormScanResult.suspicious_forms || []) {
    const suspLvl = String(suspicious.risk_level || "").toLowerCase();
    const isHighRisk = suspLvl === "yuksek" || suspLvl === "yüksek" || suspLvl === "high" ||
                      suspLvl === "kritik" || suspLvl === "kri̇ti̇k" || suspLvl === "critical";
    if (!isHighRisk) continue;
    if (indexFilter && !indexFilter.has(suspicious.form_index)) continue;
    const form = forms[suspicious.form_index];
    if (!form) continue;
    injectFormWarning(form, suspicious);
    highlightForm(form);
  }
}

async function scanForms() {
  try {
    const [{ scanPage }, { classifyForm }] = await Promise.all([formDetectorPromise, fieldClassifierPromise]);
    const result = scanPage();
    const forms = document.querySelectorAll("form");
    const pageFieldTypes = new Set();
    for (const form of forms) {
      const classified = classifyForm(form);
      for (const fieldType of classified.field_types) pageFieldTypes.add(fieldType);
    }

    lastFormScanResult = {
      ...result,
      url: location.href,
      domain: location.hostname,
      field_types: [...pageFieldTypes],
      scanned_at: Date.now(),
    };

    if (lastFormScanResult.form_count > 0) {
      chrome.runtime
        .sendMessage({
          type: "form_detected",
          form_data: lastFormScanResult,
        })
        .catch(() => {});
    }

    clearFormWarnings();
    const formLvl = String(lastFormScanResult.risk_level || "").toLowerCase();
    const formHighRisk = formLvl === "high" || formLvl === "critical" ||
                        formLvl === "yüksek" || formLvl === "yuksek" ||
                        formLvl === "kritik" || formLvl === "kri̇ti̇k";
    if (formHighRisk) {
      showFormWarnings();
    }
  } catch (error) {
    console.warn("AegisNexus Shield: form detector could not be loaded", error);
  }
}

function observeForms() {
  const observer = new MutationObserver((mutations) => {
    let hasNewForm = false;
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeName === "FORM" || node.querySelector?.("form")) {
          hasNewForm = true;
          break;
        }
      }
      if (hasNewForm) break;
    }
    if (hasNewForm) scanForms();
  });

  observer.observe(document.documentElement || document.body, {
    childList: true,
    subtree: true,
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "show_warning") {
    const domain = window.location.hostname || "";
    isDismissed(domain)
      .then((dismissed) => {
        if (dismissed) {
          sendResponse({ ok: true, shown: false, reason: "dismissed" });
          return;
        }
        renderBanner(message, domain);
        sendResponse({ ok: true, shown: true });
      })
      .catch((error) => {
        sendResponse({ ok: false, error: String(error) });
      });
    return true;
  }

  if (message?.type === "show_form_warning") {
    const formIndices = Array.isArray(message.form_indices) ? message.form_indices : null;
    showFormWarnings(formIndices);
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "GET_PAGE_SIGNALS") {
    sendResponse({
      ok: true,
      pageSignals: {
        url: location.href,
        protocol: location.protocol,
        form_scan: lastFormScanResult,
      },
    });
    return false;
  }

  if (message?.type === "go_back") {
    window.history.back();
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    scanForms();
    observeForms();
  });
} else {
  scanForms();
  observeForms();
}
