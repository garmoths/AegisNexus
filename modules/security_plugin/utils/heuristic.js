const SUSPICIOUS_TLDS = new Set(["xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "vip", "icu", "cyou", "bond", "cfd", "monster", "quest"]);

const SAFE_DOMAINS = new Set([
  "aegisnexus.dev",
  "youtube.com", "youtu.be",
  "google.com", "google.com.tr",
  "instagram.com",
  "whatsapp.com",
  "telegram.org", "t.me",
  "facebook.com", "fb.com",
  "twitter.com", "x.com",
  "linkedin.com",
  "github.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "netflix.com",
  "spotify.com",
  "wikipedia.org",
  "reddit.com",
  "discord.com",
  "twitch.tv",
  "tiktok.com",
  "pinterest.com",
  "snapchat.com",
  "zoom.us",
  "slack.com",
  "notion.so",
  "canva.com",
  "dropbox.com",
  "adobe.com",
  "cloudflare.com",
  "stackoverflow.com",
  "medium.com",
  "quora.com",
  "bbc.com", "cnn.com", "reuters.com",
  "nytimes.com", "theguardian.com",
  "gsm.org.tr", "btk.gov.tr", "tcmb.gov.tr", "turkiye.gov.tr",
]);
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
const HTTP_SENSITIVE_TERMS = ["login", "password", "account", "verify", "secure", "giris", "sifre", "odeme", "hesap", "dogrula"];
const SUSPICIOUS_WORDS = [
  "secure",
  "login",
  "verify",
  "update",
  "confirm",
  "account",
  "banking",
  "signin",
  "giris",
  "uyelik",
  "hesap",
  "dogrula",
  "guncelle",
  "odeme",
  "banka",
  "guvenli",
  "sifre",
  "kullanici",
];

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

  // Güvenli domain kontrolü: aegisnexus.dev, youtube, google vb. → 100 güvenli
  if (SAFE_DOMAINS.has(hostname)) {
    return { score: 0, flags: ["trusted-domain"], risk_level: "SAFE" };
  }
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(i).join(".");
    if (SAFE_DOMAINS.has(parent)) {
      return { score: 0, flags: ["trusted-domain"], risk_level: "SAFE" };
    }
  }
  const subdomainCount = Math.max(parts.length - 2, 0);
  const dotCount = (raw.match(/\./g) || []).length;
  const port = parsed.port ? Number(parsed.port) : null;

  if (isIpv4(hostname)) {
    score += 25;
    flags.push("ip-address-host");
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 25;
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
    score += 30;
    flags.push("http-sensitive-keyword");
  }
  if (hostname.includes("resmi")) {
    score += 20;
    flags.push("fake-official-claim");
  }
  if (/-/.test(hostname) && /\d/.test(hostname)) {
    score += 20;
    flags.push("domain-number-hyphen-combo");
  }
  if (/\d{3,}/.test(hostname)) {
    score += 15;
    flags.push("domain-consecutive-digits");
  }
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    score += 10;
    flags.push("domain-too-many-hyphens");
  }
  if (hostname.length > 30) {
    score += 15;
    flags.push("long-domain");
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
