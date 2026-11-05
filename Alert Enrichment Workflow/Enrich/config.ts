// =============================================================================
// CONFIG — every tunable threshold and limit for Alert Enrichment lives here.
// =============================================================================
export const CONFIG = {
  // Name written into trace[].component and audit records.
  COMPONENT: "Alert Enrichment",
  // The only alert record schema version this component accepts.
  SCHEMA_VERSION: "3",

  // Per-call HTTP timeout for every provider request (ms).
  CALL_TIMEOUT_MS: 8000,
  // Max provider requests in flight at once (protects provider rate limits).
  MAX_PARALLEL_CALLS: 20,
  // Max distinct IOCs looked up per alert; the rest are listed in the trace reason.
  MAX_IOCS: 25,
  // How long a successful provider result is reused from the cache (hours).
  // Errors are never cached.
  CACHE_TTL_HOURS: 24,

  // GreyNoise (ip): classification "malicious" → malicious;
  // noise/RIOT true with classification "benign" → clean; not seen → unknown.
  GREYNOISE: {
    BENIGN_NOTE: "known scanner / business service",
  },

  // AbuseIPDB (ip): score = abuseConfidenceScore.
  ABUSEIPDB: {
    MALICIOUS_MIN_SCORE: 75, // >= 75 → malicious
    SUSPICIOUS_MIN_SCORE: 25, // 25–74 → suspicious; < 25 with reports → clean
    MAX_AGE_DAYS: 90, // report window sent to /check
  },

  // VirusTotal (ip, domain, url, hash): score = malicious / total engines * 100.
  VIRUSTOTAL: {
    MALICIOUS_MIN_ENGINES: 5, // last_analysis_stats.malicious >= 5 → malicious
    SUSPICIOUS_MIN_ENGINES: 1, // 1–4 → suspicious; 0 with harmless > 0 → clean
  },

  // urlscan.io (url, domain): searches existing scans only — never submits.
  URLSCAN: {
    SUSPICIOUS_MIN_SCORE: 50, // verdicts.overall.score >= 50 → suspicious
    SEARCH_SIZE: 10, // results requested from /search
  },

  // Okta user context.
  OKTA: {
    RECENT_LOGINS: 10, // sign-in events pulled from the System Log
    LOG_LOOKBACK_DAYS: 90, // how far back to search the System Log
  },
} as const;

export const PROVIDERS_BY_TYPE = {
  ip: ["greynoise", "abuseipdb", "virustotal"],
  domain: ["virustotal", "urlscan"],
  url: ["virustotal", "urlscan"],
  hash: ["virustotal"],
} as const;
