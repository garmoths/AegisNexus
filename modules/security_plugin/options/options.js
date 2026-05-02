/* =========================================================
   AegisNexus Shield — Options Page Logic
   ========================================================= */

const byId = (id) => document.getElementById(id);

function showSpinner() {
  byId("options-spinner")?.classList.remove("hidden");
}

function hideSpinner() {
  byId("options-spinner")?.classList.add("hidden");
}

function isValidDomain(domain) {
  const re = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return re.test(domain);
}

/* =========================================================
   TAB SWITCHING
   ========================================================= */
function initTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  const panels = document.querySelectorAll(".tab-panel");

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      panels.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const target = byId(`panel-${btn.dataset.tab}`);
      if (target) target.classList.add("active");
    });
  });
}

/* =========================================================
   PERSONAL WHITELIST
   ========================================================= */
let personalWhitelist = [];

async function loadPersonalWhitelist() {
  const stored = await chrome.storage.local.get(["whitelist"]);
  personalWhitelist = Array.isArray(stored.whitelist) ? stored.whitelist : [];
  renderPersonalWhitelist();
}

function renderPersonalWhitelist() {
  const tbody = byId("pw-tbody");
  const emptyMsg = byId("pw-empty-msg");
  const table = byId("pw-table");

  if (personalWhitelist.length === 0) {
    table.classList.add("hidden");
    emptyMsg.classList.remove("hidden");
    return;
  }

  table.classList.remove("hidden");
  emptyMsg.classList.add("hidden");

  tbody.innerHTML = personalWhitelist
    .map((entry) => {
      const domain = typeof entry === "string" ? entry : entry.domain;
      const date = typeof entry === "object" && entry.added_at ? entry.added_at : "-";
      return `
        <tr>
          <td>${escapeHtml(domain)}</td>
          <td>${escapeHtml(date)}</td>
          <td><button class="btn-delete" data-domain="${escapeHtml(domain)}">🗑️ Sil</button></td>
        </tr>`;
    })
    .join("");

  tbody.querySelectorAll(".btn-delete").forEach((btn) => {
    btn.addEventListener("click", () => {
      removeFromPersonalWhitelist(btn.dataset.domain);
    });
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

async function addToPersonalWhitelist(domain) {
  const input = byId("pw-domain-input");
  const errorMsg = byId("pw-domain-error");
  const raw = domain.trim().toLowerCase();

  if (!isValidDomain(raw)) {
    errorMsg.classList.remove("hidden");
    setTimeout(() => errorMsg.classList.add("hidden"), 3000);
    return;
  }

  errorMsg.classList.add("hidden");

  const stored = await chrome.storage.local.get(["whitelist"]);
  const list = Array.isArray(stored.whitelist) ? stored.whitelist : [];

  const domains = list.map((e) => (typeof e === "string" ? e : e.domain));
  if (domains.includes(raw)) {
    input.value = "";
    return;
  }

  const newEntry = { domain: raw, added_at: new Date().toISOString() };
  const newList = [...list, newEntry];

  await chrome.storage.local.set({ whitelist: newList });
  await chrome.runtime.sendMessage({ type: "whitelist_add", domain: raw });

  personalWhitelist = newList;
  input.value = "";
  renderPersonalWhitelist();
}

async function removeFromPersonalWhitelist(domain) {
  const stored = await chrome.storage.local.get(["whitelist"]);
  const list = Array.isArray(stored.whitelist) ? stored.whitelist : [];

  const newList = list.filter((e) => {
    const d = typeof e === "string" ? e : e.domain;
    return d !== domain;
  });

  await chrome.storage.local.set({ whitelist: newList });
  await chrome.runtime.sendMessage({ type: "whitelist_remove", domain });

  personalWhitelist = newList;
  renderPersonalWhitelist();
}

async function verifyPersonalWhitelist() {
  showSpinner();
  const verifyBtn = byId("pw-verify-btn");
  const resultBox = byId("pw-verify-result");

  verifyBtn.disabled = true;
  verifyBtn.textContent = "⏳ Doğrulanıyor...";

  try {
    const stored = await chrome.storage.local.get(["api_base_url", "whitelist"]);
    const base = String(stored.api_base_url || "http://127.0.0.1:8000").trim().replace(/\/+$/g, "");
    const list = Array.isArray(stored.whitelist) ? stored.whitelist : [];

    let safeCount = 0;
    let removedCount = 0;
    const verifiedList = [];

    for (const entry of list) {
      const domain = typeof entry === "string" ? entry : entry.domain;

      try {
        const resp = await fetch(`${base}/api/v2/phishing/check-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: `https://${domain}` }),
        });

        if (resp.ok) {
          const data = await resp.json();
          const score = Number(data.score || 0);

          if (score >= 80) {
            safeCount++;
            verifiedList.push(entry);
          } else {
            removedCount++;
          }
        } else {
          safeCount++;
          verifiedList.push(entry);
        }
      } catch {
        safeCount++;
        verifiedList.push(entry);
      }
    }

    await chrome.storage.local.set({ whitelist: verifiedList });
    personalWhitelist = verifiedList;
    renderPersonalWhitelist();

    resultBox.classList.remove("hidden");
    resultBox.innerHTML = `
      <div class="verify-stat"><span class="label">Toplam kontrol edilen</span><span class="value">${list.length}</span></div>
      <div class="verify-stat"><span class="label">Güvenli (kaldı)</span><span class="value" style="color:#86efac">${safeCount}</span></div>
      <div class="verify-stat"><span class="label">Çıkarılan (güvenli değil)</span><span class="value" style="color:#fca5a5">${removedCount}</span></div>
    `;
  } finally {
    hideSpinner();
    verifyBtn.disabled = false;
    verifyBtn.textContent = "🔄 Şimdi Doğrula";
  }
}

/* =========================================================
   GLOBAL WHITELIST
   ========================================================= */
let globalWhitelist = [];

async function loadGlobalWhitelist() {
  const stored = await chrome.storage.local.get(["global_whitelist", "global_whitelist_updated"]);
  globalWhitelist = Array.isArray(stored.global_whitelist) ? stored.global_whitelist : [];

  const lastUpdated = stored.global_whitelist_updated
    ? new Date(stored.global_whitelist_updated).toLocaleString("tr-TR")
    : "-";
  byId("gw-last-updated").textContent = `Son güncelleme: ${lastUpdated}`;

  renderGlobalWhitelist();
}

function renderGlobalWhitelist(filter = "") {
  const tbody = byId("gw-tbody");
  const emptyMsg = byId("gw-empty-msg");
  const table = byId("gw-table");
  const badge = byId("gw-count-badge");

  const filtered = filter
    ? globalWhitelist.filter((d) => d.toLowerCase().includes(filter.toLowerCase()))
    : globalWhitelist;

  badge.textContent = `${globalWhitelist.length} domain`;

  if (filtered.length === 0) {
    table.classList.add("hidden");
    emptyMsg.classList.remove("hidden");
    emptyMsg.textContent = filter ? "Arama sonucu bulunamadı" : "Yükleniyor...";
    return;
  }

  table.classList.remove("hidden");
  emptyMsg.classList.add("hidden");

  tbody.innerHTML = filtered
    .map((domain) => {
      return `
        <tr>
          <td>${escapeHtml(domain)}</td>
          <td><span class="status-badge status-verified">✅ Doğrulanmış</span></td>
        </tr>`;
    })
    .join("");
}

async function refreshGlobalWhitelist() {
  showSpinner();
  const btn = byId("gw-refresh-btn");
  btn.disabled = true;
  btn.textContent = "⏳ Güncelleniyor...";

  try {
    const stored = await chrome.storage.local.get(["api_base_url"]);
    const base = String(stored.api_base_url || "http://127.0.0.1:8000").trim().replace(/\/+$/g, "");

    const resp = await fetch(`${base}/api/v2/whitelist/global`);
    if (!resp.ok) throw new Error("Failed to fetch global whitelist");

    const data = await resp.json();
    const domains = Array.isArray(data.domains) ? data.domains : [];

    await chrome.storage.local.set({
      global_whitelist: domains,
      global_whitelist_updated: new Date().toISOString(),
    });

    globalWhitelist = domains;
    const lastUpdated = new Date().toLocaleString("tr-TR");
    byId("gw-last-updated").textContent = `Son güncelleme: ${lastUpdated}`;
    renderGlobalWhitelist(byId("gw-filter-input").value.trim());
  } catch (err) {
    console.warn("AegisNexus Shield: global whitelist refresh failed", err);
  } finally {
    hideSpinner();
    btn.disabled = false;
    btn.textContent = "🔄 Güncelle";
  }
}

/* =========================================================
   SETTINGS
   ========================================================= */
async function loadSettings() {
  const stored = await chrome.storage.local.get(["api_base_url", "gsb_api_key", "aegis_key"]);
  byId("opt-api-base-url").value = String(stored.api_base_url || "");
  byId("opt-gsb-api-key").value = String(stored.gsb_api_key || "");
  byId("opt-aegis-key").value = String(stored.aegis_key || "");
}

async function saveSettings() {
  const apiBaseUrl = byId("opt-api-base-url").value.trim();
  const gsbApiKey = byId("opt-gsb-api-key").value.trim();
  const aegisKey = byId("opt-aegis-key").value.trim();

  await chrome.storage.local.set({
    api_base_url: apiBaseUrl,
    gsb_api_key: gsbApiKey,
    aegis_key: aegisKey,
  });

  const btn = byId("btn-save-options");
  const original = btn.textContent;
  btn.textContent = "✅ Kaydedildi!";
  btn.style.transform = "scale(1.02)";
  setTimeout(() => {
    btn.textContent = original;
    btn.style.transform = "";
  }, 1200);
}

function bindPasswordToggles() {
  const pairs = [
    { input: "opt-gsb-api-key", btn: "toggle-gsb-key" },
    { input: "opt-aegis-key", btn: "toggle-aegis-key" },
  ];

  pairs.forEach(({ input, btn }) => {
    byId(btn)?.addEventListener("click", () => {
      const inp = byId(input);
      const show = inp.type === "password";
      inp.type = show ? "text" : "password";
      byId(btn).textContent = show ? "Gizle" : "Göster";
    });
  });
}

/* =========================================================
   INIT
   ========================================================= */
async function init() {
  initTabs();
  bindPasswordToggles();

  // Personal Whitelist
  byId("pw-add-btn").addEventListener("click", () => {
    const input = byId("pw-domain-input");
    addToPersonalWhitelist(input.value);
  });

  byId("pw-domain-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      addToPersonalWhitelist(e.target.value);
    }
  });

  byId("pw-verify-btn").addEventListener("click", () => {
    verifyPersonalWhitelist();
  });

  // Global Whitelist
  byId("gw-filter-input").addEventListener("input", (e) => {
    renderGlobalWhitelist(e.target.value.trim());
  });

  byId("gw-refresh-btn").addEventListener("click", () => {
    refreshGlobalWhitelist();
  });

  // Settings
  byId("btn-save-options").addEventListener("click", () => {
    saveSettings();
  });

  await loadPersonalWhitelist();
  await loadGlobalWhitelist();
  await loadSettings();
}

init().catch((err) => {
  console.warn("AegisNexus Shield: options init failed", err);
});
