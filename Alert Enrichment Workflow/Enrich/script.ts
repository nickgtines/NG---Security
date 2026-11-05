import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { ADAPTERS, errorEntry } from "./adapters";
import { CONFIG, PROVIDERS_BY_TYPE } from "./config";
import { lookup_crowdstrike_host, lookup_okta_user } from "./entities";
import { cacheGet, cachePut, detectIocType, hashTypeOf, isDomain, isNonRoutableIp, isUrl, limiter, log, setLogContext, type IocResult, type IocType, type Provider } from "./lib";

const started = performance.now();
const STATUS_TEXT: Record<number, string> = { 200: "OK", 400: "Bad Request", 405: "Method Not Allowed" };

function respond(status: number, body: unknown): never {
  const json = JSON.stringify(body);
  process.stdout.write(`HTTP/1.1 ${status} ${STATUS_TEXT[status] ?? "OK"}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n${json}`);
  log("info", "enrich_completed", `Responded ${status}.`, { status, bytes: json.length, duration_ms: Math.round(performance.now() - started) });
  process.exit(0);
}
function bad(message: string): never {
  log("warn", "input_rejected", message);
  respond(400, { error: "invalid_alert_record", message });
}

function runUrl(): string | null {
  const e = process.env;
  if (e._3B_RUN_URL) return e._3B_RUN_URL;
  return null;
}

// ---------------------------------------------------------------- input
// Accepts an HTTP request (route /enrich) or raw JSON from a linked step (Enrich test, Lookup API).
async function readBody(): Promise<string> {
  const raw = await Bun.stdin.text();
  const m = raw.match(/^([A-Z]+) (\S+) HTTP\/\d(?:\.\d)?\r?\n/);
  if (!m) return raw;
  if (m[1] !== "POST") {
    log("warn", "input_rejected", "Non-POST request.", { method: m[1] });
    respond(405, { error: "method_not_allowed", message: "Use POST /enrich with an alert record (schema_version 3) as the JSON body." });
  }
  const sep = raw.indexOf("\r\n\r\n");
  return sep === -1 ? "" : raw.slice(sep + 4);
}

const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStrOrNull = (v: unknown) => v === null || v === undefined || typeof v === "string";
const strArr = (v: unknown) => v === undefined || (Array.isArray(v) && v.every((x) => typeof x === "string"));

function validate(rec: any): string | null {
  if (!isObj(rec)) return "Body must be a JSON object (the alert record).";
  if (rec.schema_version !== CONFIG.SCHEMA_VERSION) return `schema_version must be "${CONFIG.SCHEMA_VERSION}" (got ${JSON.stringify(rec.schema_version ?? null)}).`;
  if (typeof rec.correlation_id !== "string" || !rec.correlation_id) return "correlation_id must be a non-empty string.";
  const a = rec.alert;
  if (!isObj(a)) return "alert must be an object.";
  if (typeof a.id !== "string" || !a.id) return "alert.id must be a non-empty string.";
  if (!["sentinel", "crowdstrike"].includes(a.source)) return 'alert.source must be "sentinel" or "crowdstrike".';
  if (a.user !== undefined && a.user !== null && !(isObj(a.user) && isStrOrNull(a.user.upn))) return "alert.user must be an object with upn string|null.";
  if (a.host !== undefined && a.host !== null && !(isObj(a.host) && isStrOrNull(a.host.hostname) && isStrOrNull(a.host.device_id)))
    return "alert.host must be an object with hostname and device_id as string|null.";
  if (a.iocs !== undefined && a.iocs !== null) {
    if (!isObj(a.iocs)) return "alert.iocs must be an object.";
    for (const k of ["ips", "domains", "urls"]) if (!strArr(a.iocs[k])) return `alert.iocs.${k} must be an array of strings.`;
    const h = a.iocs.hashes;
    if (h !== undefined && !(Array.isArray(h) && h.every((x) => isObj(x) && ["md5", "sha1", "sha256"].includes(x.type) && typeof x.value === "string")))
      return 'alert.iocs.hashes must be an array of { type: "md5"|"sha1"|"sha256", value: string }.';
  }
  if (!Array.isArray(rec.trace)) return "trace must be an array.";
  return null;
}

// ---------------------------------------------------------------- IOC lookups
const pool = limiter(CONFIG.MAX_PARALLEL_CALLS);

async function runAdapter(provider: Provider, ioc: string, ioc_type: IocType, hash_type?: string): Promise<IocResult> {
  const t0 = performance.now();
  const hit = await cacheGet(provider, ioc, ioc_type);
  if (hit) {
    log("info", "ioc_lookup", `${provider} cache hit.`, { provider, ioc, ioc_type, verdict: hit.verdict, latency_ms: Math.round(performance.now() - t0), cache: "hit" });
    return hit;
  }
  let r: IocResult;
  try {
    r = await pool(() => ADAPTERS[provider](ioc, ioc_type));
  } catch (e) {
    r = errorEntry(ioc, ioc_type, provider, e);
  }
  if (hash_type) r.details = { ...r.details, hash_type };
  log(r.error ? "warn" : "info", "ioc_lookup", r.error ? `${provider} lookup failed.` : `${provider} lookup done.`, {
    provider, ioc, ioc_type, verdict: r.verdict, latency_ms: Math.round(performance.now() - t0), cache: "miss", error: r.error,
  });
  await cachePut(r);
  return r;
}

function lookupIoc(ioc: string, ioc_type: IocType, hash_type?: string) {
  return PROVIDERS_BY_TYPE[ioc_type].map((p) => runAdapter(p, ioc, ioc_type, hash_type));
}

function summarize(results: IocResult[]) {
  const s = { malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
  for (const r of results) s[r.verdict]++;
  return s;
}

interface Candidate { ioc: string; ioc_type: IocType; hash_type?: string }

function collectIocs(iocs: any) {
  const picked: Candidate[] = [];
  const skipped: { ioc: string; why: string }[] = [];
  const seen = new Set<string>();
  const add = (c: Candidate) => {
    const k = `${c.ioc_type}|${c.ioc}`;
    if (seen.has(k)) return;
    seen.add(k);
    picked.push(c);
  };
  for (const raw of iocs?.ips ?? []) {
    const ip = raw.trim();
    if (!isIP(ip)) skipped.push({ ioc: ip, why: "invalid IP" });
    else if (isNonRoutableIp(ip)) skipped.push({ ioc: ip, why: "private/loopback/link-local" });
    else add({ ioc: ip, ioc_type: "ip" });
  }
  for (const raw of iocs?.domains ?? []) {
    const d = raw.trim().toLowerCase().replace(/\.$/, "");
    isDomain(d) ? add({ ioc: d, ioc_type: "domain" }) : skipped.push({ ioc: raw, why: "invalid domain" });
  }
  for (const raw of iocs?.urls ?? []) {
    const u = raw.trim();
    isUrl(u) ? add({ ioc: u, ioc_type: "url" }) : skipped.push({ ioc: raw, why: "invalid URL" });
  }
  for (const h of iocs?.hashes ?? []) {
    const v = h.value.trim().toLowerCase();
    hashTypeOf(v) === h.type ? add({ ioc: v, ioc_type: "hash", hash_type: h.type }) : skipped.push({ ioc: h.value, why: `not a valid ${h.type}` });
  }
  const over = picked.slice(CONFIG.MAX_IOCS);
  for (const o of over) skipped.push({ ioc: o.ioc, why: `over ${CONFIG.MAX_IOCS}-IOC limit` });
  return { picked: picked.slice(0, CONFIG.MAX_IOCS), skipped };
}

function describeSkipped(skipped: { ioc: string; why: string }[]) {
  if (!skipped.length) return "";
  const groups = new Map<string, string[]>();
  for (const s of skipped) groups.set(s.why, [...(groups.get(s.why) ?? []), s.ioc]);
  return ` Skipped ${skipped.length}: ` + [...groups].map(([why, list]) => `${why} (${list.join(", ")})`).join("; ") + ".";
}

// ---------------------------------------------------------------- lookup mode (/lookup page)
async function lookupMode(body: any) {
  const value = body?.lookup?.ioc;
  setLogContext({ correlation_id: `lookup-${randomUUID()}` });
  if (typeof value !== "string" || !value.trim()) bad("lookup.ioc must be a non-empty string.");
  const d = detectIocType(value);
  if (!d) bad(`Couldn't detect an IOC type for "${value.slice(0, 200)}". Enter an IP, domain, URL (with http/https) or an MD5/SHA1/SHA256 hash.`);
  if (d.ioc_type === "ip" && isNonRoutableIp(d.ioc)) bad(`${d.ioc} is a private, loopback or link-local address; it isn't sent to reputation providers.`);
  log("info", "lookup_started", "Single-IOC lookup.", { ioc: d.ioc, ioc_type: d.ioc_type });
  const results = await Promise.all(lookupIoc(d.ioc, d.ioc_type, d.hash_type));
  respond(200, { ioc: d.ioc, ioc_type: d.ioc_type, hash_type: d.hash_type ?? null, ioc_results: results, ioc_summary: summarize(results), duration_ms: Math.round(performance.now() - started) });
}

// ---------------------------------------------------------------- main
const text = await readBody();
let body: any;
try {
  body = JSON.parse(text);
} catch {
  bad("Body is not valid JSON.");
}
if (isObj(body) && isObj(body.lookup) && body.schema_version === undefined) await lookupMode(body);

const problem = validate(body);
if (problem) bad(problem);
const rec = body;
setLogContext({ correlation_id: rec.correlation_id, alert_id: rec.alert.id });
log("info", "enrich_started", "Enriching alert.", { source: rec.alert.source });

const enrichment: any = { ioc_results: [], ioc_summary: summarize([]), user_context: null, host_context: null };
let decision = "ENRICHED";
let reason = "";
let traceError: string | null = null;
try {
  const { picked, skipped } = collectIocs(rec.alert.iocs);
  for (const s of skipped) log("warn", "ioc_skipped", `Skipped IOC: ${s.why}.`, { ioc: s.ioc, why: s.why });
  const upn: string | null = rec.alert.user?.upn || null;
  const hostname: string | null = rec.alert.host?.hostname || null;
  const deviceId: string | null = rec.alert.host?.device_id || null;

  const [iocSettled, userCtx, hostCtx] = await Promise.all([
    Promise.all(picked.flatMap((c) => lookupIoc(c.ioc, c.ioc_type, c.hash_type))),
    upn ? lookup_okta_user(upn) : Promise.resolve(null),
    hostname || deviceId ? lookup_crowdstrike_host(hostname, deviceId) : Promise.resolve(null),
  ]);
  enrichment.ioc_results = iocSettled;
  enrichment.ioc_summary = summarize(iocSettled);
  enrichment.user_context = userCtx;
  enrichment.host_context = hostCtx;

  const errs = [
    ...iocSettled.filter((r) => r.error).map((r) => `${r.provider} ${r.ioc}: ${r.error}`),
    ...(userCtx?.error ? [`okta: ${userCtx.error}`] : []),
    ...(hostCtx?.error ? [`crowdstrike: ${hostCtx.error}`] : []),
  ];
  const cached = iocSettled.filter((r) => r.cached).length;
  const s = enrichment.ioc_summary;
  const parts: string[] = [];
  if (picked.length === 0) {
    decision = "NO_IOCS";
    parts.push(skipped.length ? "No IOCs eligible for reputation lookup." : "Alert has no IOCs; no reputation lookups made.");
  } else {
    parts.push(
      `Looked up ${picked.length} IOC(s) with ${iocSettled.length} provider result(s) (${cached} cached): ${s.malicious} malicious, ${s.suspicious} suspicious, ${s.clean} clean, ${s.unknown} unknown.`,
    );
  }
  parts.push(userCtx ? `Okta user status ${userCtx.status}.` : "No user UPN; Okta skipped.");
  parts.push(hostCtx ? (hostCtx.found ? `CrowdStrike host found (${hostCtx.containment_status ?? "status unknown"}).` : "CrowdStrike host not found.") : "No host; CrowdStrike skipped.");
  reason = parts.join(" ") + describeSkipped(skipped);
  if (errs.length) {
    if (decision === "ENRICHED") decision = "ENRICHED_PARTIAL";
    traceError = `${errs.length} lookup error(s): ${errs.join("; ")}`.slice(0, 1000);
  }
} catch (e: any) {
  decision = "ENRICHMENT_ERROR";
  traceError = `unexpected error: ${e?.message ?? String(e)}`;
  reason = "Enrichment failed unexpectedly; returning whatever was collected.";
  log("error", "enrich_failed", "Unexpected enrichment error; returning record.", { error: traceError });
}

rec.enrichment = enrichment;
rec.trace.push({
  component: CONFIG.COMPONENT,
  decision,
  reason,
  duration_ms: Math.round(performance.now() - started),
  run_url: runUrl(),
  error: traceError,
});
respond(200, rec);
