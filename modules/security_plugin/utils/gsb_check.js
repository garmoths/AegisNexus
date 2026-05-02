const GSB_TIMEOUT_MS = 5000;
const GSB_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

async function checkURL(url) {
  const stored = await chrome.storage.local.get(["gsb_api_key"]);
  const apiKey = String(stored.gsb_api_key || "").trim();
  if (!apiKey) return { skipped: true };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), GSB_TIMEOUT_MS);

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client: {
            clientId: "aegisnexus-shield",
            clientVersion: "1.0.0",
          },
          threatInfo: {
            threatTypes: GSB_THREAT_TYPES,
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
        signal: controller.signal,
      }
    );

    if (!response.ok) {
      return { threat_found: false, threat_type: null, source: "gsb" };
    }

    const data = await response.json();
    const firstMatch = Array.isArray(data?.matches) && data.matches.length > 0 ? data.matches[0] : null;
    return {
      threat_found: Boolean(firstMatch),
      threat_type: firstMatch?.threatType || null,
      source: "gsb",
    };
  } catch {
    return { threat_found: false, threat_type: null, source: "gsb" };
  } finally {
    clearTimeout(timeoutId);
  }
}

export { checkURL };
