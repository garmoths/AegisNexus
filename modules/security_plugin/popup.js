function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  byId(id).textContent = String(value);
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

function riskLabel(score) {
  if (score >= 80) return `Yüksek (${score})`;
  if (score >= 60) return `Orta (${score})`;
  return `Düşük (${score})`;
}

async function loadPopupData() {
  const activeTab = await getActiveTab();
  const url = activeTab?.url || "";

  setText("site-host", "-");
  setText("risk-score", "-");
  setText("protocol", "-");

  if (!url || !/^https?:/i.test(url)) {
    setText("site-host", "Desteklenmeyen sekme");
  } else {
    const analyzeResponse = await chrome.runtime.sendMessage({
      type: "ANALYZE_URL",
      url,
    });
    const result = analyzeResponse?.result || null;

    if (result) {
      setText("site-host", result.host || url);
      setText("risk-score", riskLabel(result.score || 0));
      setText("protocol", result.https ? "HTTPS" : "HTTP");
    }
  }

  if (activeTab?.id) {
    try {
      const pageSignalsResponse = await chrome.tabs.sendMessage(activeTab.id, {
        type: "GET_PAGE_SIGNALS",
      });
      const pageSignals = pageSignalsResponse?.pageSignals;
      if (pageSignals) {
        setText("password-inputs", pageSignals.passwordInputs);
        setText("insecure-forms", pageSignals.insecureForms);
        setText("mixed-content", pageSignals.mixedContentCandidates);
      }
    } catch {
      // Content script may not run on restricted browser pages.
      setText("password-inputs", "N/A");
      setText("insecure-forms", "N/A");
      setText("mixed-content", "N/A");
    }
  }

  const stored = await chrome.storage.local.get(["stats"]);
  const stats = stored.stats || {
    scanned: 0,
    risky: 0,
    notifications: 0,
  };
  setText("stats-scanned", stats.scanned || 0);
  setText("stats-risky", stats.risky || 0);
  setText("stats-notifications", stats.notifications || 0);
}

loadPopupData();
