// One adapter per provider. Each takes (ioc, ioc_type), calls its provider through the
// step's attached connector (auth is injected; no credentials in code) and returns one
// ioc_results entry with the raw provider response in details.raw. Adapters throw
// CallError on timeout / 429 / HTTP errors; runAdapter() turns that into an error entry.
import { CONFIG } from "./config";
import { CallError, ensureOk, fetchJson, type IocResult, type IocType, type Provider, type Verdict } from "./lib";

function entry(ioc: string, ioc_type: IocType, provider: Provider, verdict: Verdict, score: number | null, details: Record<string, unknown>): IocResult {
  return { ioc, ioc_type, provider, verdict, score, details, cached: false, error: null };
}

// ---------------------------------------------------------------- GreyNoise (ip)
export async function lookup_greynoise(ioc: string, ioc_type: IocType): Promise<IocResult> {
  const r = await fetchJson(`https://api.greynoise.io/v3/community/${encodeURIComponent(ioc)}`);
  ensureOk(r, [404]);
  const j = r.json ?? {};
  if (r.status === 404 || (j.noise === false && j.riot === false && !j.classification)) {
    return entry(ioc, ioc_type, "greynoise", "unknown", null, { raw: j, note: "not seen by GreyNoise" });
  }
  if (j.classification === "malicious") return entry(ioc, ioc_type, "greynoise", "malicious", null, { raw: j });
  if ((j.noise === true || j.riot === true) && j.classification === "benign") {
    return entry(ioc, ioc_type, "greynoise", "clean", null, { raw: j, note: CONFIG.GREYNOISE.BENIGN_NOTE });
  }
  return entry(ioc, ioc_type, "greynoise", "unknown", null, { raw: j });
}

// ---------------------------------------------------------------- AbuseIPDB (ip)
export async function lookup_abuseipdb(ioc: string, ioc_type: IocType): Promise<IocResult> {
  const q = new URLSearchParams({ ipAddress: ioc, maxAgeInDays: String(CONFIG.ABUSEIPDB.MAX_AGE_DAYS) });
  const r = await fetchJson(`https://api.abuseipdb.com/api/v2/check?${q}`);
  ensureOk(r);
  const d = r.json?.data;
  const score = typeof d?.abuseConfidenceScore === "number" ? d.abuseConfidenceScore : null;
  const reports = Number(d?.totalReports ?? 0);
  let verdict: Verdict = "unknown";
  if (score !== null && score >= CONFIG.ABUSEIPDB.MALICIOUS_MIN_SCORE) verdict = "malicious";
  else if (score !== null && score >= CONFIG.ABUSEIPDB.SUSPICIOUS_MIN_SCORE) verdict = "suspicious";
  else if (score !== null && reports > 0) verdict = "clean";
  return entry(ioc, ioc_type, "abuseipdb", verdict, score, { raw: r.json });
}

// ---------------------------------------------------------------- VirusTotal (ip, domain, url, hash)
const VT_PATH: Record<IocType, (ioc: string) => string> = {
  ip: (i) => `ip_addresses/${encodeURIComponent(i)}`,
  domain: (i) => `domains/${encodeURIComponent(i)}`,
  url: (i) => `urls/${Buffer.from(i).toString("base64url")}`,
  hash: (i) => `files/${encodeURIComponent(i)}`,
};
export async function lookup_virustotal(ioc: string, ioc_type: IocType): Promise<IocResult> {
  const r = await fetchJson(`https://www.virustotal.com/api/v3/${VT_PATH[ioc_type](ioc)}`);
  ensureOk(r, [404]);
  if (r.status === 404) return entry(ioc, ioc_type, "virustotal", "unknown", null, { raw: r.json, note: "not found in VirusTotal" });
  const stats = r.json?.data?.attributes?.last_analysis_stats ?? {};
  const total = Object.values(stats).reduce<number>((a, v) => a + (typeof v === "number" ? v : 0), 0);
  const malicious = Number(stats.malicious ?? 0);
  const harmless = Number(stats.harmless ?? 0);
  const score = total > 0 ? Math.round((malicious / total) * 100) : null;
  let verdict: Verdict = "unknown";
  if (malicious >= CONFIG.VIRUSTOTAL.MALICIOUS_MIN_ENGINES) verdict = "malicious";
  else if (malicious >= CONFIG.VIRUSTOTAL.SUSPICIOUS_MIN_ENGINES) verdict = "suspicious";
  else if (malicious === 0 && harmless > 0) verdict = "clean";
  return entry(ioc, ioc_type, "virustotal", verdict, score, { raw: r.json });
}

// ---------------------------------------------------------------- urlscan.io (url, domain)
// Searches existing scans only; never submits a new scan.
function urlscanQuery(ioc: string, ioc_type: IocType) {
  if (ioc_type === "domain") return `page.domain:${ioc.replace(/[^a-z0-9.\-_]/gi, "")}`;
  return `page.url:"${ioc.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
export async function lookup_urlscan(ioc: string, ioc_type: IocType): Promise<IocResult> {
  const q = new URLSearchParams({ q: urlscanQuery(ioc, ioc_type), size: String(CONFIG.URLSCAN.SEARCH_SIZE) });
  const s = await fetchJson(`https://urlscan.io/api/v1/search/?${q}`);
  ensureOk(s);
  const results: any[] = s.json?.results ?? [];
  if (results.length === 0) return entry(ioc, ioc_type, "urlscan", "unknown", null, { raw: { search: s.json }, note: "no existing scans" });
  // Newest scan's verdicts (search hits don't always carry them).
  const latest = results[0];
  let verdicts = latest.verdicts;
  let resultRaw: any = null;
  if (!verdicts && latest._id) {
    const res = await fetchJson(`https://urlscan.io/api/v1/result/${encodeURIComponent(latest._id)}/`);
    ensureOk(res, [404]);
    if (res.status !== 404) {
      verdicts = res.json?.verdicts;
      resultRaw = { task: res.json?.task, page: res.json?.page, verdicts: res.json?.verdicts };
    }
  }
  const overall = verdicts?.overall ?? {};
  const rawScore = typeof overall.score === "number" ? overall.score : null;
  const score = rawScore === null ? null : Math.max(0, Math.min(100, Math.round(rawScore)));
  let verdict: Verdict = "clean";
  if (overall.malicious === true) verdict = "malicious";
  else if (rawScore !== null && rawScore >= CONFIG.URLSCAN.SUSPICIOUS_MIN_SCORE) verdict = "suspicious";
  return entry(ioc, ioc_type, "urlscan", verdict, score, {
    raw: { search: s.json, latest_result: resultRaw },
    scans_found: results.length,
    latest_scan: latest._id ?? null,
  });
}

export const ADAPTERS: Record<Provider, (ioc: string, t: IocType) => Promise<IocResult>> = {
  greynoise: lookup_greynoise,
  abuseipdb: lookup_abuseipdb,
  virustotal: lookup_virustotal,
  urlscan: lookup_urlscan,
};

export function errorEntry(ioc: string, ioc_type: IocType, provider: Provider, e: unknown): IocResult {
  const msg = e instanceof CallError ? e.message : `adapter error: ${(e as any)?.message ?? String(e)}`;
  return { ioc, ioc_type, provider, verdict: "unknown", score: null, details: {}, cached: false, error: msg };
}
