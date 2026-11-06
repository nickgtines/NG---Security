// Shared ingest helpers: normalizers, IOC extraction, record building, contract check.
// Identical copy lives in each Ingest step (steps cannot import across directories).
import { createHash, randomUUID } from "node:crypto";

export const COMPONENT = "alert-orchestrator.ingest";
export class InputError extends Error {}

const SEVERITIES = ["informational", "low", "medium", "high", "critical"];
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : typeof v === "number" ? String(v) : null);
const arr = (v: unknown): any[] => (Array.isArray(v) ? v : v == null ? [] : [v]);
const uniq = <T>(xs: T[]) => [...new Set(xs)];

export function log(correlationId: string | null, event: string, data: Record<string, unknown> = {}) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), component: COMPONENT, correlation_id: correlationId, run_id: process.env._3B_RUN_ID ?? null, event, ...data }));
}

// ---------- IOC helpers ----------
export function isPrivateIp(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s.includes(":")) return s === "::1" || s === "::" || /^f[cd]/.test(s) || /^fe[89ab]/.test(s);
  const p = s.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true; // not a valid IPv4 → never an IOC
  const [a, b] = p;
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}
const isIp = (v: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v);
export function hashType(v: string): "md5" | "sha1" | "sha256" | null {
  if (!/^[0-9a-f]+$/i.test(v)) return null;
  return v.length === 32 ? "md5" : v.length === 40 ? "sha1" : v.length === 64 ? "sha256" : null;
}

export type Iocs = { ips: string[]; domains: string[]; urls: string[]; hashes: { type: "md5" | "sha1" | "sha256"; value: string }[] };
export function buildIocs(raw: { ips?: unknown[]; domains?: unknown[]; urls?: unknown[]; hashes?: unknown[] }): Iocs {
  const ips = uniq(arr(raw.ips).map(str).filter((v): v is string => !!v && isIp(v)).map((v) => v.toLowerCase()).filter((v) => !isPrivateIp(v))).sort();
  const domains = uniq(arr(raw.domains).map(str).filter((v): v is string => !!v).map((v) => v.toLowerCase().replace(/\.$/, "")).filter((v) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v) && !isIp(v))).sort();
  const urls = uniq(arr(raw.urls).map(str).filter((v): v is string => !!v && /^https?:\/\//i.test(v))).sort();
  const seen = new Set<string>();
  const hashes: Iocs["hashes"] = [];
  for (const h of arr(raw.hashes).map(str)) {
    const t = h ? hashType(h) : null;
    if (!h || !t || seen.has(h.toLowerCase())) continue;
    seen.add(h.toLowerCase());
    hashes.push({ type: t, value: h.toLowerCase() });
  }
  hashes.sort((x, y) => x.value.localeCompare(y.value));
  return { ips, domains, urls, hashes };
}

const toIso = (v: unknown): string | null => {
  const s = str(v);
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
};
const sev = (v: unknown): string => {
  const s = (str(v) ?? "").toLowerCase();
  if (s === "info" || s === "informational") return "informational";
  return SEVERITIES.includes(s) ? s : "";
};
// "InitialAccess" → "Initial Access"
const tacticName = (t: string) => t.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/_/g, " ").trim();
const splitList = (v: unknown) => arr(v).flatMap((x) => (typeof x === "string" ? x.split(",") : [])).map((x) => x.trim()).filter(Boolean);

// ---------- Microsoft Sentinel ----------
// Accepts a SecurityAlert row (AlertName, Entities, …) or an Incident (properties.title, …, with
// properties.alerts[0] as the SecurityAlert). Optional SignInLogs rows become signin evidence.
export function normalize_sentinel(payload: unknown) {
  if (!isObj(payload)) throw new InputError("Sentinel payload must be a JSON object.");
  const inc = isObj(payload.properties) ? payload.properties : null;
  const a: Record<string, any> = inc ? (isObj(arr(inc.alerts)[0]) ? arr(inc.alerts)[0] : {}) : payload;
  let entities = arr(a.Entities ?? inc?.relatedEntities);
  if (typeof a.Entities === "string") { try { entities = JSON.parse(a.Entities); } catch { throw new InputError("Sentinel Entities is not valid JSON."); } }
  const ents = entities.filter(isObj).map((e) => ({ ...e, Type: String(e.Type ?? e.kind ?? "").toLowerCase() }));
  const ofType = (t: string) => ents.filter((e) => e.Type === t);

  const acct = ofType("account")[0];
  const upn = acct ? str(acct.UPN ?? acct.UserPrincipalName ?? (acct.Name && acct.UPNSuffix ? `${acct.Name}@${acct.UPNSuffix}` : acct.Name)) : null;
  const host = ofType("host")[0];
  const signins = arr(a.SignInLogs ?? payload.SignInLogs).filter(isObj);
  const ipEnts = ofType("ip");
  const allIps = uniq([...ipEnts.map((e) => str(e.Address)), ...signins.map((s) => str(s.IPAddress))].filter((v): v is string => !!v));
  const countries = uniq([...ipEnts.map((e) => str(e.Location?.CountryCode)), ...signins.map((s) => str(s.Location ?? s.LocationDetails?.countryOrRegion))]
    .filter((v): v is string => !!v).map((v) => v.toUpperCase())).sort();

  const alert = {
    id: str(a.SystemAlertId ?? inc?.incidentNumber ?? payload.name) ?? "",
    source: "sentinel",
    source_url: str(a.AlertLink ?? inc?.incidentUrl),
    rule_name: str(a.AlertName ?? inc?.title) ?? "",
    title: str(a.DisplayName ?? inc?.title ?? a.AlertName) ?? "",
    description: str(a.Description ?? inc?.description) ?? "",
    severity: sev(a.AlertSeverity ?? a.Severity ?? inc?.severity),
    tactics: uniq(splitList(a.Tactics ?? inc?.additionalData?.tactics).map(tacticName)),
    techniques: uniq(splitList(a.Techniques ?? inc?.additionalData?.techniques).map((t) => t.toUpperCase())),
    first_seen: toIso(a.StartTime ?? inc?.firstActivityTimeUtc) ?? "",
    last_seen: toIso(a.EndTime ?? inc?.lastActivityTimeUtc ?? a.StartTime) ?? "",
    user: { upn: upn ? upn.toLowerCase() : null, display_name: acct ? str(acct.DisplayName ?? acct.FullName) : null },
    host: { hostname: host ? str(host.HostName ?? host.NetBiosName) : null, device_id: host ? str(host.AzureID ?? host.MdatpDeviceId) : null, os: host ? str(host.OSFamily ?? host.OSVersion) : null },
    network: { source_ips: allIps.sort(), destination_ips: [] as string[], countries },
    iocs: buildIocs({
      ips: allIps,
      domains: ofType("dns").map((e) => e.DomainName),
      urls: ofType("url").map((e) => e.Url),
      hashes: ofType("filehash").map((e) => e.Value),
    }),
    evidence: signins.map((s) => ({
      type: "signin",
      timestamp: toIso(s.TimeGenerated) ?? "",
      details: { ip: str(s.IPAddress), country: str(s.Location)?.toUpperCase() ?? null, result: String(s.ResultType ?? ""), client_app: str(s.ClientAppUsed), app: str(s.AppDisplayName) },
    })),
    raw: payload,
  };
  return alert;
}

// ---------- CrowdStrike Falcon ----------
// Accepts a Falcon detection (detection_id, device, behaviors[]) as returned by /detects/entities/summaries.
export function normalize_crowdstrike(payload: unknown) {
  if (!isObj(payload)) throw new InputError("CrowdStrike payload must be a JSON object.");
  const d = payload;
  const dev = isObj(d.device) ? d.device : {};
  const behaviors = arr(d.behaviors).filter(isObj);
  const b0 = behaviors[0] ?? {};
  const user = str(b0.user_principal ?? b0.user_name);
  const iocVal = (t: string) => behaviors.filter((b) => String(b.ioc_type ?? "").toLowerCase() === t).map((b) => b.ioc_value);
  const netIps = behaviors.flatMap((b) => arr(b.network_accesses)).filter(isObj).map((n) => n.remote_address);
  const domains = [...iocVal("domain"), ...behaviors.flatMap((b) => arr(b.dns_requests)).filter(isObj).map((r) => r.domain_name)];
  const alert = {
    id: str(d.detection_id ?? d.composite_id) ?? "",
    source: "crowdstrike",
    source_url: str(d.falcon_host_link ?? d.falcon_link),
    rule_name: str(b0.scenario ?? b0.display_name ?? d.name) ?? "",
    title: str(d.name ?? b0.display_name ?? b0.scenario) ?? "",
    description: str(b0.description ?? d.description) ?? "",
    severity: sev(d.max_severity_displayname ?? b0.severity_name),
    tactics: uniq(behaviors.map((b) => str(b.tactic)).filter((v): v is string => !!v)),
    techniques: uniq(behaviors.map((b) => str(b.technique_id)).filter((v): v is string => !!v).map((t) => t.toUpperCase())),
    first_seen: toIso(d.first_behavior ?? b0.timestamp) ?? "",
    last_seen: toIso(d.last_behavior ?? b0.timestamp) ?? "",
    user: { upn: user && user.includes("@") ? user.toLowerCase() : user, display_name: str(b0.user_name) },
    host: { hostname: str(dev.hostname), device_id: str(dev.device_id), os: str(dev.os_version ?? dev.platform_name) },
    network: {
      source_ips: uniq([dev.external_ip, dev.local_ip].map(str).filter((v): v is string => !!v)).sort(),
      destination_ips: uniq(netIps.map(str).filter((v): v is string => !!v)).sort(),
      countries: [] as string[],
    },
    iocs: buildIocs({
      ips: [dev.external_ip, ...netIps, ...iocVal("ipv4"), ...iocVal("ipv6")],
      domains,
      urls: iocVal("url"),
      hashes: behaviors.flatMap((b) => [b.sha256, b.md5, ...(["sha256", "md5", "sha1"].includes(String(b.ioc_type)) ? [b.ioc_value] : [])]),
    }),
    evidence: behaviors.map((b) => ({
      type: b.cmdline ? "process" : "other",
      timestamp: toIso(b.timestamp) ?? "",
      details: { filename: str(b.filename), command_line: str(b.cmdline), sha256: str(b.sha256), parent: str(b.parent_details?.parent_cmdline), tactic: str(b.tactic), technique_id: str(b.technique_id) },
    })),
    raw: payload,
  };
  return alert;
}

// ---------- Record ----------
export function dedupKey(a: { rule_name: string; user: { upn: string | null }; host: { hostname: string | null } }) {
  return createHash("sha256").update(`${a.rule_name}|${a.user.upn ?? ""}|${a.host.hostname ?? ""}`.toLowerCase()).digest("hex");
}

export function buildRecord(alert: Record<string, any>, correlationId = randomUUID()) {
  return {
    schema_version: "3", correlation_id: correlationId, alert, dedup_key: dedupKey(alert as any),
    case: { id: null, url: null, status: null },
    triage: null, enrichment: null, investigation: null, response: null, trace: [] as any[],
  };
}

const ISO = (v: unknown) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T/.test(v) && !isNaN(Date.parse(v));
const strArr = (v: unknown) => Array.isArray(v) && v.every((x) => typeof x === "string");
const strOrNull = (v: unknown) => v === null || typeof v === "string";

// Returns a list of contract violations (empty = valid).
export function checkContract(r: Record<string, any>): string[] {
  const e: string[] = [];
  const a = r.alert ?? {};
  if (r.schema_version !== "3") e.push('schema_version must be "3"');
  if (typeof r.correlation_id !== "string" || !r.correlation_id) e.push("correlation_id missing");
  if (!/^[0-9a-f]{64}$/.test(r.dedup_key)) e.push("dedup_key must be sha256 hex");
  for (const k of ["id", "rule_name", "title"]) if (typeof a[k] !== "string" || !a[k]) e.push(`alert.${k} is required`);
  if (typeof a.description !== "string") e.push("alert.description must be a string");
  if (!["sentinel", "crowdstrike"].includes(a.source)) e.push("alert.source must be sentinel or crowdstrike");
  if (!strOrNull(a.source_url)) e.push("alert.source_url must be string|null");
  if (!SEVERITIES.includes(a.severity)) e.push(`alert.severity must be one of ${SEVERITIES.join(", ")}`);
  if (!strArr(a.tactics) || !strArr(a.techniques)) e.push("alert.tactics and alert.techniques must be string arrays");
  if (!ISO(a.first_seen)) e.push("alert.first_seen must be ISO 8601");
  if (!ISO(a.last_seen)) e.push("alert.last_seen must be ISO 8601");
  if (!isObj(a.user) || !strOrNull(a.user.upn) || !strOrNull(a.user.display_name)) e.push("alert.user is malformed");
  if (!isObj(a.host) || !strOrNull(a.host.hostname) || !strOrNull(a.host.device_id) || !strOrNull(a.host.os)) e.push("alert.host is malformed");
  if (!a.user?.upn && !a.host?.hostname) e.push("alert needs at least one of user.upn or host.hostname");
  const n = a.network ?? {};
  if (!strArr(n.source_ips) || !strArr(n.destination_ips) || !strArr(n.countries)) e.push("alert.network arrays are malformed");
  const i = a.iocs ?? {};
  if (!strArr(i.ips) || !strArr(i.domains) || !strArr(i.urls) || !Array.isArray(i.hashes)) e.push("alert.iocs is malformed");
  if (!Array.isArray(a.evidence) || a.evidence.some((x: any) => !["signin", "process", "file", "url", "ip", "other"].includes(x?.type) || !ISO(x?.timestamp) || !isObj(x?.details)))
    e.push("alert.evidence entries need a valid type, ISO timestamp and details object");
  if (!isObj(a.raw)) e.push("alert.raw must be an object");
  for (const k of ["triage", "enrichment", "investigation", "response"]) if (r[k] !== null) e.push(`${k} must be null at ingest`);
  if (!Array.isArray(r.trace)) e.push("trace must be an array");
  return e;
}

// ---------- HTTP ----------
export function parseRequest(raw: string) {
  const i = raw.indexOf("\r\n\r\n");
  const head = i >= 0 ? raw.slice(0, i) : raw;
  const [method = "", target = "/"] = (head.split("\r\n")[0] ?? "").split(" ");
  return { method: method.toUpperCase(), path: target, body: i >= 0 ? raw.slice(i + 4) : "" };
}

// Shared ingest flow. Emits an envelope for the Orchestrate step on stdout.
export async function ingest(source: "sentinel" | "crowdstrike", normalizer: (p: unknown) => Record<string, any>) {
  const started = Date.now();
  const raw = await Bun.stdin.text();
  const correlationId = randomUUID();
  const fail = (status: number, error: string) => {
    log(correlationId, "ingest_rejected", { source, status, error });
    const trace = [{ component: COMPONENT, decision: "rejected", reason: `Invalid ${source} input: ${error}`, duration_ms: Date.now() - started, run_url: process.env._3B_RUN_URL || null, error }];
    process.stdout.write(JSON.stringify({ kind: "invalid", status, source, correlation_id: correlationId, error, trace }));
  };
  const req = parseRequest(raw);
  if (req.method !== "POST") return fail(405, "Use POST with a JSON body.");
  let payload: unknown;
  try { payload = JSON.parse(req.body); } catch { return fail(400, "Body is not valid JSON."); }
  let alert: Record<string, any>;
  try { alert = normalizer(payload); } catch (e) { return fail(400, (e as Error).message); }
  const record = buildRecord(alert, correlationId);
  const errs = checkContract(record);
  if (errs.length) return fail(400, `Record does not match contract v3: ${errs.join("; ")}.`);
  log(correlationId, "ingest_ok", { source, alert_id: alert.id, dedup_key: record.dedup_key, iocs: alert.iocs, duration_ms: Date.now() - started });
  process.stdout.write(JSON.stringify({ kind: "record", source, ingest_ms: Date.now() - started, record }));
}
