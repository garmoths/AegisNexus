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

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "vip",
  "icu", "cyou", "bond", "cfd", "monster", "quest",
  "club", "online", "site", "click", "zip",
]);

const TRUSTED_TLDS = new Set(["com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "k12.tr"]);
const BRAND_KEYWORDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "instagram", "netflix", "twitter", "linkedin", "bankofamerica",
  "wellsfargo", "chase", "steam", "discord", "binance", "coinbase",
  "ziraat", "garanti", "akbank", "isbank", "yapi-kredi", "halkbank",
  "edevlet", "turkiye",
];

const HTTP_SENSITIVE_TERMS = [
  "login", "password", "account", "verify", "secure",
  "giris", "sifre", "odeme", "hesap", "dogrula",
];

const SUSPICIOUS_WORDS = [
  "secure", "login", "verify", "update", "confirm", "account",
  "banking", "signin", "free", "bonus", "crypto", "wallet",
  "giris", "uyelik", "hesap", "dogrula", "guncelle", "odeme",
  "banka", "guvenli", "sifre", "kullanici",
];

const SUSPICIOUS_EXTENSIONS = new Set([".exe", ".zip", ".rar", ".scr", ".bat", ".cmd", ".pif"]);

function getRiskLevel(safetyScore) {
  if (safetyScore >= 80) return "GÜVENLİ";
  if (safetyScore >= 60) return "İYİ";
  if (safetyScore >= 40) return "ORTA";
  if (safetyScore >= 20) return "RİSKLİ";
  return "KRİTİK";
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

function hasTrustedTld(hostname) {
  for (const tld of TRUSTED_TLDS) {
    if (hostname.endsWith(`.${tld}`) || hostname === tld) return true;
  }
  return false;
}

function hasSuspiciousExtension(pathname) {
  const lower = pathname.toLowerCase();
  for (const ext of SUSPICIOUS_EXTENSIONS) {
    if (lower.endsWith(ext)) return true;
  }
  return false;
}

function hasRedirectPattern(raw, hostname) {
  const afterDomain = raw.slice(raw.indexOf(hostname) + hostname.length);
  return afterDomain.includes("//");
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
  let score = 100;
  let forcedRiskLevel = null;

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { score: 0, flags: ["invalid-url"], risk_level: "KRİTİK" };
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
  const hyphenCount = (hostname.match(/-/g) || []).length;

  // ── Protokol ──────────────────────────────────────────────────────────
  if (protocol === "http:") {
    score -= 11;
    flags.push("no-https");
  }

  if (protocol === "http:" && HTTP_SENSITIVE_TERMS.some((term) => fullLower.includes(term))) {
    score -= 22;
    flags.push("http-sensitive-keyword");
  }

  // ── Host ──────────────────────────────────────────────────────────────
  if (isIpv4(hostname)) {
    score -= 26;
    flags.push("ip-address-host");
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    score -= 19;
    flags.push("suspicious-tld");
  }

  if (subdomainCount > 3) {
    score -= 11;
    flags.push("too-many-subdomains");
  }

  if (hasBrandSpoof(hostname)) {
    score -= 22;
    flags.push("brand-subdomain-spoof");
  }

  if (hostname.includes("resmi")) {
    score -= 15;
    flags.push("fake-official-claim");
  }

  if (hostname.length > 30) {
    score -= 11;
    flags.push("long-domain");
  }

  if (/-/.test(hostname) && /\d/.test(hostname)) {
    score -= 15;
    flags.push("domain-number-hyphen");
  }

  if (/\d{3,}/.test(hostname)) {
    score -= 11;
    flags.push("consecutive-digits");
  }

  if (hyphenCount >= 3) {
    score -= 7;
    flags.push("dash-domain-heavy");
  } else if (hyphenCount >= 1) {
    score -= 4;
    flags.push("dash-domain-mild");
  }

  // ── URL Yapısı ────────────────────────────────────────────────────────
  if (raw.length > 120) {
    score -= 11;
    flags.push("url-too-long-120");
  } else if (raw.length > 75) {
    score -= 7;
    flags.push("url-too-long-75");
  }

  if (raw.includes("@")) {
    score -= 15;
    flags.push("at-symbol");
  }

  if (hasHexEncoding(raw)) {
    score -= 7;
    flags.push("hex-encoding");
  }

  if (hasDoubleEncoding(raw)) {
    score -= 15;
    flags.push("double-encoding");
  }

  if (hasHomographChars(raw)) {
    score -= 19;
    flags.push("homograph-characters");
  }

  if (hasRedirectPattern(raw, hostname)) {
    score -= 7;
    flags.push("redirect-pattern");
  }

  if (hasSuspiciousExtension(pathname)) {
    score -= 15;
    flags.push("suspicious-ext");
  }

  if (dotCount > 5) {
    score -= 7;
    flags.push("too-many-dots");
  }

  if (port !== null && port !== 80 && port !== 443) {
    score -= 11;
    flags.push("non-standard-port");
  }

  // ── Şüpheli Kelimeler ─────────────────────────────────────────────────
  const suspiciousWordHits = countMatchedSuspiciousWords(fullLower);
  if (suspiciousWordHits > 0) {
    score -= Math.min(suspiciousWordHits * 6, 22);
    flags.push("suspicious-keywords");
  }

  // ── Dış Sinyal Seçenekleri ────────────────────────────────────────────
  if (options.bloomMatched === true) {
    score -= 15;
    flags.push("bloom-suspect-domain");
  }

  if (options.dnsResult?.consensus_blocked === true) {
    score -= 30;
    flags.push("dns-consensus-blocked");
  } else if (options.dnsResult?.cloudflare_blocked || options.dnsResult?.quad9_blocked) {
    score -= 15;
    flags.push("dns-provider-blocked");
  }

  if (options.gsbResult?.threat_found === true) {
    score -= 37;
    flags.push("gsb-threat");
    forcedRiskLevel = "KRİTİK";
  }

  // ── Bonus ─────────────────────────────────────────────────────────────
  if (protocol === "https:" && suspiciousWordHits === 0) {
    score += 10;
  }

  if (hasTrustedTld(hostname)) {
    score += 10;
  }

  score = Math.max(0, Math.min(100, score));
  return { score, flags, risk_level: forcedRiskLevel || getRiskLevel(score) };
}

export { analyzeURL, getRiskLevel };
