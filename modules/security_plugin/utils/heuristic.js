const SUSPICIOUS_TLDS = new Set(["xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc"]);
const BRAND_KEYWORDS = [
  "paypal",
  "google",
  "microsoft",
  "apple",
  "amazon",
  "facebook",
  "instagram",
  "netflix",
  "twitter",
  "linkedin",
  "bankofamerica",
  "wellsfargo",
  "chase",
  "steam",
  "discord",
  "binance",
  "coinbase",
];
const HTTP_SENSITIVE_TERMS = ["login", "password", "account", "verify", "secure"];
const SUSPICIOUS_WORDS = ["secure", "login", "verify", "update", "confirm", "account", "banking", "signin"];

function getRiskLevel(score) {
  if (score <= 20) return "SAFE";
  if (score <= 40) return "LOW";
  if (score <= 60) return "MEDIUM";
  if (score <= 80) return "HIGH";
  return "CRITICAL";
}

function isIpv4(hostname) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
}

function hasHomographChars(value) {
  return /[\u0370-\u03FF\u0400-\u04FF]/u.test(value);
}

function hasHexEncoding(value) {
  return /%[0-9a-fA-F]{2}/.test(value);
}

function hasDoubleEncoding(value) {
  return /%25[0-9a-fA-F]{2}/.test(value);
}

function hasBrandSpoof(hostname) {
  const labels = hostname.split(".").filter(Boolean);
  if (labels.length < 3) return false;
  const subdomains = labels.slice(0, -2).join(".");
  return BRAND_KEYWORDS.some((brand) => subdomains.includes(brand));
}

function countMatchedSuspiciousWords(text) {
  let hits = 0;
  for (const word of SUSPICIOUS_WORDS) {
    if (text.includes(word)) hits += 1;
  }
  return hits;
}

function analyzeURL(rawUrl, options = {}) {
  const flags = [];
  let score = 0;
  let forcedRiskLevel = null;

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { score: 0, flags: ["invalid-url"], risk_level: "SAFE" };
  }

  const raw = String(rawUrl || "");
  const protocol = (parsed.protocol || "").toLowerCase();
  const hostname = (parsed.hostname || "").toLowerCase();
  const pathname = (parsed.pathname || "").toLowerCase();
  const search = (parsed.search || "").toLowerCase();
  const fullLower = `${hostname}${pathname}${search}`.toLowerCase();
  const parts = hostname.split(".").filter(Boolean);
  const tld = parts.length ? parts[parts.length - 1] : "";
  const subdomainCount = Math.max(parts.length - 2, 0);
  const dotCount = (raw.match(/\./g) || []).length;
  const port = parsed.port ? Number(parsed.port) : null;

  if (isIpv4(hostname)) {
    score += 25;
    flags.push("ip-address-host");
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 20;
    flags.push("suspicious-tld");
  }
  if (raw.length > 75) {
    score += 15;
    flags.push("long-url");
  }
  if (raw.includes("@")) {
    score += 20;
    flags.push("at-symbol");
  }
  if (subdomainCount > 3) {
    score += 15;
    flags.push("too-many-subdomains");
  }
  if (hasBrandSpoof(hostname)) {
    score += 30;
    flags.push("brand-subdomain-spoof");
  }
  if (hasHexEncoding(raw)) {
    score += 10;
    flags.push("hex-encoding");
  }
  if (hasDoubleEncoding(raw)) {
    score += 20;
    flags.push("double-encoding");
  }
  if (hasHomographChars(raw)) {
    score += 25;
    flags.push("homograph-characters");
  }
  if (protocol === "http:" && HTTP_SENSITIVE_TERMS.some((term) => fullLower.includes(term))) {
    score += 20;
    flags.push("http-sensitive-keyword");
  }

  const suspiciousWordHits = countMatchedSuspiciousWords(fullLower);
  if (suspiciousWordHits > 0) {
    score += Math.min(suspiciousWordHits * 5, 20);
    flags.push("suspicious-keywords");
  }
  if (port !== null && port !== 80 && port !== 443) {
    score += 15;
    flags.push("non-standard-port");
  }
  if (dotCount > 5) {
    score += 10;
    flags.push("too-many-dots");
  }
  if (options.bloomMatched === true) {
    score += 20;
    flags.push("bloom-suspect-domain");
  }
  if (options.dnsResult?.consensus_blocked === true) {
    score += 40;
    flags.push("dns-consensus-blocked");
  } else if (options.dnsResult?.cloudflare_blocked || options.dnsResult?.quad9_blocked) {
    score += 20;
    flags.push("dns-provider-blocked");
  }
  if (options.gsbResult?.threat_found === true) {
    score += 50;
    flags.push("gsb-threat");
    forcedRiskLevel = "CRITICAL";
  }

  score = Math.min(score, 100);
  return { score, flags, risk_level: forcedRiskLevel || getRiskLevel(score) };
}

export { analyzeURL };
