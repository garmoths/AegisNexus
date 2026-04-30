class BloomFilter {
  constructor(size, hashCount) {
    this.size = Number.isInteger(size) && size > 0 ? size : 4096;
    this.hashCount = Number.isInteger(hashCount) && hashCount > 0 ? hashCount : 6;
    this.bitArray = new Uint8Array(this.size);
  }

  normalizeDomain(domain) {
    return String(domain || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  }

  fnv1aHash(input, seed) {
    let hash = (0x811c9dc5 ^ seed) >>> 0;
    for (let i = 0; i < input.length; i += 1) {
      hash ^= input.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash >>> 0;
  }

  getIndices(domain) {
    const normalized = this.normalizeDomain(domain);
    if (!normalized) return [];

    const indices = [];
    for (let i = 0; i < this.hashCount; i += 1) {
      const seed = (i + 1) * 0x9e3779b1;
      const hash = this.fnv1aHash(normalized, seed >>> 0);
      indices.push(hash % this.size);
    }
    return indices;
  }

  add(domain) {
    const indices = this.getIndices(domain);
    for (const idx of indices) {
      this.bitArray[idx] = 1;
    }
  }

  mightContain(domain) {
    const indices = this.getIndices(domain);
    if (indices.length === 0) return false;
    for (const idx of indices) {
      if (this.bitArray[idx] !== 1) return false;
    }
    return true;
  }

  loadFromArray(domains) {
    if (!Array.isArray(domains)) return;
    for (const domain of domains) {
      this.add(domain);
    }
  }

  async saveToStorage() {
    await chrome.storage.local.set({
      bloom_data: {
        size: this.size,
        hashCount: this.hashCount,
        bits: Array.from(this.bitArray),
      },
    });
  }

  async loadFromStorage() {
    const stored = await chrome.storage.local.get(["bloom_data"]);
    const data = stored.bloom_data;
    if (!data || !Array.isArray(data.bits)) return false;
    if (data.size !== this.size || data.hashCount !== this.hashCount) return false;
    if (data.bits.length !== this.size) return false;

    this.bitArray = Uint8Array.from(data.bits.map((b) => (b ? 1 : 0)));
    return true;
  }
}

export { BloomFilter };
