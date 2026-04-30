const heuristicModulePromise = import(chrome.runtime.getURL("utils/heuristic.js"));

// Quick page-level checks run early at document_start.
const state = {
  insecureForms: 0,
  passwordInputs: 0,
  mixedContentCandidates: 0,
  urlRisk: null,
};

function inspectPage() {
  const forms = document.querySelectorAll("form");
  const passwordInputs = document.querySelectorAll('input[type="password"]');

  let insecureForms = 0;
  forms.forEach((form) => {
    const action = (form.getAttribute("action") || "").trim();
    if (action.startsWith("http://")) insecureForms += 1;
  });

  let mixedContentCandidates = 0;
  document.querySelectorAll("img, script, iframe").forEach((el) => {
    const src = (el.getAttribute("src") || "").trim();
    if (src.startsWith("http://")) mixedContentCandidates += 1;
  });

  state.insecureForms = insecureForms;
  state.passwordInputs = passwordInputs.length;
  state.mixedContentCandidates = mixedContentCandidates;
}

function showWarningBannerIfNeeded() {
  const score = state.urlRisk?.score || 0;
  const shouldWarn =
    location.protocol !== "https:" ||
    state.insecureForms > 0 ||
    state.mixedContentCandidates > 0 ||
    score >= 60;

  if (!shouldWarn || document.getElementById("aegisnexus-shield-banner")) return;

  const banner = document.createElement("div");
  banner.id = "aegisnexus-shield-banner";
  banner.textContent = "AegisNexus Shield: Bu sayfada güvenlik riski olabilecek ögeler tespit edildi.";
  banner.style.cssText = [
    "position:fixed",
    "top:0",
    "left:0",
    "right:0",
    "z-index:2147483647",
    "padding:10px 14px",
    "font-size:13px",
    "font-family:Arial, sans-serif",
    "background:#7f1d1d",
    "color:#ffffff",
    "text-align:center",
    "box-shadow:0 2px 8px rgba(0,0,0,.25)",
  ].join(";");

  document.documentElement.appendChild(banner);
}

function showRuntimeWarningBanner(payload = {}) {
  let banner = document.getElementById("aegisnexus-shield-banner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "aegisnexus-shield-banner";
    banner.style.cssText = [
      "position:fixed",
      "top:0",
      "left:0",
      "right:0",
      "z-index:2147483647",
      "padding:10px 14px",
      "font-size:13px",
      "font-family:Arial, sans-serif",
      "background:#7f1d1d",
      "color:#ffffff",
      "text-align:center",
      "box-shadow:0 2px 8px rgba(0,0,0,.25)",
    ].join(";");
    document.documentElement.appendChild(banner);
  }

  const level = payload.risk_level || "HIGH";
  const score = Number(payload.score || 0);
  banner.textContent = `AegisNexus Shield Uyarisi: Risk ${level} (${score}/100)`;
}

async function analyzeCurrentURL() {
  try {
    const { analyzeURL } = await heuristicModulePromise;
    state.urlRisk = analyzeURL(location.href);
  } catch (error) {
    console.warn("AegisNexus Shield: heuristic module could not be loaded", error);
    state.urlRisk = { score: 0, flags: [], risk_level: "SAFE" };
  }
}

inspectPage();
analyzeCurrentURL();

// Re-check after the DOM settles for lazy-loaded elements.
window.addEventListener("DOMContentLoaded", () => {
  inspectPage();
  analyzeCurrentURL().then(() => {
    showWarningBannerIfNeeded();
  });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "show_warning") {
    showRuntimeWarningBanner(message);
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type !== "GET_PAGE_SIGNALS") return false;

  inspectPage();
  analyzeCurrentURL().then(() => {
    sendResponse({
      ok: true,
      pageSignals: {
        url: location.href,
        protocol: location.protocol,
        insecureForms: state.insecureForms,
        passwordInputs: state.passwordInputs,
        mixedContentCandidates: state.mixedContentCandidates,
        urlRisk: state.urlRisk,
      },
    });
  });
  return true;
});
