const DNS_TIMEOUT_MS = 3000;

function isBlockedDnsStatus(status) {
  return status === 2 || status === 5; // SERVFAIL(2), REFUSED(5)
}

async function queryDnsProvider(endpoint, domain) {
  if (!domain) return { blocked: false };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);

  try {
    const response = await fetch(`${endpoint}?name=${encodeURIComponent(domain)}&type=A`, {
      method: "GET",
      headers: {
        Accept: "application/dns-json",
      },
      signal: controller.signal,
    });

    if (!response.ok) return { blocked: false };

    const data = await response.json();
    const status = typeof data?.Status === "number" ? data.Status : null;
    return { blocked: isBlockedDnsStatus(status) };
  } catch {
    // Network/timeout errors are non-fatal for scoring flow.
    return { blocked: false };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function checkDomainViaDNS(domain) {
  const [cloudflareResult, quad9Result] = await Promise.allSettled([
    queryDnsProvider("https://cloudflare-dns.com/dns-query", domain),
    queryDnsProvider("https://dns.quad9.net/dns-query", domain),
  ]);

  const cloudflare_blocked =
    cloudflareResult.status === "fulfilled" ? Boolean(cloudflareResult.value?.blocked) : false;
  const quad9_blocked =
    quad9Result.status === "fulfilled" ? Boolean(quad9Result.value?.blocked) : false;

  return {
    cloudflare_blocked,
    quad9_blocked,
    consensus_blocked: cloudflare_blocked && quad9_blocked,
    source: "dns",
  };
}

export { checkDomainViaDNS };
