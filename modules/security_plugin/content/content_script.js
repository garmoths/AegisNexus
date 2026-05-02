const BANNER_HOST_ID = "aegisnexus-shield-warning-host";

function getBannerColor(riskLevel) {
  if (riskLevel === "CRITICAL") return "#dc2626";
  if (riskLevel === "HIGH") return "#ea580c";
  if (riskLevel === "MEDIUM") return "#ca8a04";
  return "#ca8a04";
}

function buildFlagsText(flags) {
  if (!Array.isArray(flags) || flags.length === 0) return "Flags: none";
  const compact = flags.slice(0, 5).join(", ");
  return `Flags: ${compact}`;
}

async function isDismissed(domain) {
  const key = `dismissed:${domain}`;
  const data = await chrome.storage.session.get([key]);
  return data[key] === true;
}

async function markDismissed(domain) {
  const key = `dismissed:${domain}`;
  await chrome.storage.session.set({ [key]: true });
}

function removeBanner() {
  const existing = document.getElementById(BANNER_HOST_ID);
  if (existing) existing.remove();
}

function ensureMountPoint() {
  if (document.body) return document.body;
  return document.documentElement;
}

function renderBanner({ risk_level, score, flags }, domain) {
  removeBanner();

  const mount = ensureMountPoint();
  if (!mount) return;

  const host = document.createElement("div");
  host.id = BANNER_HOST_ID;
  mount.appendChild(host);

  const shadow = host.attachShadow({ mode: "closed" });
  const background = getBannerColor(String(risk_level || "MEDIUM").toUpperCase());
  const safeScore = Number(score || 0);
  const safeRisk = String(risk_level || "MEDIUM").toUpperCase();

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
        font-family: Arial, sans-serif;
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
        <div class="aegis-message">⚠️ Bu site tehlikeli olabilir! Risk: ${safeRisk} | Skor: ${safeScore}</div>
        <div class="aegis-actions">
          <button class="aegis-btn" id="aegis-continue">Yine de Devam Et</button>
          <button class="aegis-btn" id="aegis-back">Geri Dön</button>
        </div>
      </div>
      <div class="aegis-flags">${buildFlagsText(flags)}</div>
    </div>
  `;

  shadow.appendChild(wrapper);

  const continueButton = wrapper.querySelector("#aegis-continue");
  const backButton = wrapper.querySelector("#aegis-back");

  continueButton?.addEventListener("click", () => {
    markDismissed(domain)
      .catch(() => {})
      .finally(() => removeBanner());
  });

  backButton?.addEventListener("click", () => {
    history.back();
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "show_warning") return false;

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
});
