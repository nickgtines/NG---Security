// Alert Triage core logic (shared contract v3). Deterministic, no AI.
import { readdirSync, readFileSync, existsSync } from "node:fs";
import config from "./config.json";

export const COMPONENT = "alert-triage";
const KG_DIR = "/storage/known-good/entries";
const KG_SEEDED = "/storage/known-good/.seeded";
const HTTP_TIMEOUT_MS = 10_000;

export const SEED_ENTRIES: KnownGoodEntry[] = [
  { id: "seed-svc-backup", type: "service_account", value: "svc-backup@contoso.com", reason: "Nightly backup service account", owner: "it-ops@contoso.com", expires_at: null },
  { id: "seed-vulnscan01", type: "scanner", value: "VULNSCAN01", reason: "Authorized vulnerability scanner", owner: "secops@contoso.com", expires_at: null },
];

export type KnownGoodEntry = {
  id: string; type: "service_account" | "scanner" | "break_glass" | "host";
  value: string; reason: string; owner: string; expires_at: string | null;
};
type CheckResult = "match" | "no_match" | "error";
type Check = { name: string; result: CheckResult; detail: string };
type CheckOutcome = Check & { entry?: Record<string, unknown>; case_id?: string | null };

let correlationId = "unknown";
export function log(event: string, data: Record<string, unknown> = {}) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), component: COMPONENT, correlation_id: correlationId, run_id: process.env._3B_RUN_ID ?? null, event, ...data }));
}

export class ContractError extends Error {}

const SOURCES = ["sentinel", "crowdstrike"];
const SEVERITIES = ["informational", "low", "medium", "high", "critical"];
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStrOrNull = (v: unknown) => v === null || typeof v === "string";

export function validate(rec: unknown): asserts rec is Record<string, any> {
  const errs: string[] = [];
  if (!isObj(rec)) throw new ContractError("Body must be a JSON object (alert record, schema_version 3).");
  if (rec.schema_version !== "3") errs.push('schema_version must be "3"');
  if (typeof rec.correlation_id !== "string" || !rec.correlation_id) errs.push("correlation_id must be a non-empty string");
  if (typeof rec.dedup_key !== "string" || !/^[0-9a-f]{64}$/i.test(rec.dedup_key)) errs.push("dedup_key must be a 64-character hex sha256");
  if (!Array.isArray(rec.trace)) errs.push("trace must be an array");
  if ("triage" in rec && rec.triage !== null && !isObj(rec.triage)) errs.push("triage must be null or an object");
  const a = rec.alert;
  if (!isObj(a)) errs.push("alert must be an object");
  else {
    for (const k of ["id", "rule_name", "title"]) if (typeof a[k] !== "string" || !a[k]) errs.push(`alert.${k} must be a non-empty string`);
    if (!SOURCES.includes(a.source)) errs.push(`alert.source must be one of ${SOURCES.join(", ")}`);
    if (!SEVERITIES.includes(a.severity)) errs.push(`alert.severity must be one of ${SEVERITIES.join(", ")}`);
    if (!isObj(a.user) || !isStrOrNull(a.user.upn)) errs.push("alert.user must be an object with upn string|null");
    if (!isObj(a.host) || !isStrOrNull(a.host.hostname)) errs.push("alert.host must be an object with hostname string|null");
  }
  if (errs.length) throw new ContractError(`Invalid alert record: ${errs.join("; ")}.`);
}

// ---------- Check 1: known-good list in volume ----------
export function loadKnownGood(): KnownGoodEntry[] {
  if (!existsSync(KG_SEEDED) && !existsSync(KG_DIR)) return SEED_ENTRIES; // volume not initialised yet
  if (!existsSync(KG_DIR)) return [];
  return readdirSync(KG_DIR).filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(readFileSync(`${KG_DIR}/${f}`, "utf8")) as KnownGoodEntry);
}

export function known_good_list_check(upn: string | null, hostname: string | null, now = new Date()): CheckOutcome {
  const name = "known_good_list_check";
  log("check_start", { check: name, input: { upn, hostname } });
  let out: CheckOutcome;
  try {
    const all = loadKnownGood();
    const active = all.filter((e) => !e.expires_at || new Date(e.expires_at).getTime() > now.getTime());
    const expired = all.length - active.length;
    const candidates = [upn, hostname].filter((v): v is string => !!v).map((v) => v.toLowerCase());
    const hit = active.find((e) => candidates.includes(String(e.value).toLowerCase()));
    out = hit
      ? { name, result: "match", detail: `${hit.type} entry "${hit.value}" matched (owner ${hit.owner}: ${hit.reason}).`, entry: { check: name, ...hit } }
      : { name, result: "no_match", detail: `No active entry for upn=${upn ?? "null"} host=${hostname ?? "null"} (${active.length} active, ${expired} expired ignored).` };
  } catch (e) {
    out = { name, result: "error", detail: `Could not read known-good list: ${(e as Error).message}` };
  }
  log("check_result", { check: name, result: out.result, detail: out.detail });
  return out;
}

// ---------- Check 2: Okta group membership ----------
async function okta(path: string) {
  const base = process.env.OKTA_ORG_URL!.replace(/\/+$/, "");
  return fetch(`${base}${path}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
}

export async function known_good_okta_check(upn: string | null): Promise<CheckOutcome> {
  const name = "known_good_okta_check";
  const group = config.okta_known_good_group;
  log("check_start", { check: name, input: { upn, group } });
  let out: CheckOutcome;
  try {
    if (!upn) out = { name, result: "no_match", detail: "Alert has no user.upn to look up in Okta." };
    else {
      const ur = await okta(`/api/v1/users/${encodeURIComponent(upn)}`);
      if (ur.status === 404) out = { name, result: "no_match", detail: `User ${upn} not found in Okta.` };
      else if (!ur.ok) throw new Error(`Okta user lookup returned HTTP ${ur.status}`);
      else {
        const user = await ur.json();
        let next: string | null = `/api/v1/users/${encodeURIComponent(user.id)}/groups?limit=200`;
        let found: any = null;
        while (next && !found) {
          const gr = await okta(next);
          if (!gr.ok) throw new Error(`Okta group lookup returned HTTP ${gr.status}`);
          const groups = await gr.json();
          found = groups.find((g: any) => g?.profile?.name === group);
          const m = (gr.headers.get("link") ?? "").match(/<([^>]+)>;\s*rel="next"/);
          next = m ? new URL(m[1]).pathname + new URL(m[1]).search : null;
        }
        out = found
          ? { name, result: "match", detail: `${upn} is a member of Okta group "${group}".`, entry: { check: name, type: "okta_group", value: upn, group, group_id: found.id, okta_user_id: user.id } }
          : { name, result: "no_match", detail: `${upn} exists in Okta but is not in group "${group}".` };
      }
    }
  } catch (e) {
    out = { name, result: "error", detail: `Okta check failed: ${(e as Error).message}` };
  }
  log("check_result", { check: name, result: out.result, detail: out.detail });
  return out;
}

// ---------- Check 3: duplicate open case in Tines Cases ----------
// Uses POST /api/v3/cases/search, which supports tag + status + created_at filters (verified),
// so no local dedup index is needed.
export async function duplicate_check(dedupKey: string): Promise<CheckOutcome> {
  const name = "duplicate_check";
  const tag = `dedup:${dedupKey}`;
  const hours = config.dedup_window_hours;
  log("check_start", { check: name, input: { tag, window_hours: hours, status: "open" } });
  let out: CheckOutcome;
  try {
    const base = "https://" + process.env.TINES_URL!.replace(/^(https?:\/\/)+/, "").replace(/\/+$/, "");
    const r = await fetch(`${base}/api/v3/cases/search`, {
      method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      body: JSON.stringify({
        filter: { op: "AND", nodes: [
          { field: "status", operator: "IS", value: "open" },
          { field: "tag", operator: "IS", value: tag },
          { field: "created_at", operator: "IN_THE_LAST", value: `${hours}h` },
        ] },
        sort: [{ field: "created_at", direction: "DESC" }], page: { size: 1 }, include_total: true,
      }),
    });
    const text = await r.text();
    if (r.status === 400 && /Unknown tag name/i.test(text)) {
      out = { name, result: "no_match", detail: `No case has ever been tagged ${tag}.` };
    } else if (!r.ok) throw new Error(`Tines case search returned HTTP ${r.status}: ${text.slice(0, 200)}`);
    else {
      const body = JSON.parse(text);
      const c = body.cases?.[0];
      out = c
        ? { name, result: "match", detail: `Open case ${c.case_id} ("${c.name}") created ${c.created_at} has tag ${tag} (${body.total ?? 1} open match(es) in last ${hours}h).`, case_id: String(c.case_id) }
        : { name, result: "no_match", detail: `No open case tagged ${tag} created in the last ${hours}h.` };
    }
  } catch (e) {
    out = { name, result: "error", detail: `Duplicate check failed: ${(e as Error).message}` };
  }
  log("check_result", { check: name, result: out.result, detail: out.detail, matched_case_id: out.case_id ?? null });
  return out;
}

// ---------- Orchestration ----------
export function runUrl(): string | null {
  // 3B does not expose a run URL to step code (only _3B_RUN_ID, which every log line carries).
  return process.env._3B_RUN_URL || null;
}

export async function triage(rec: Record<string, any>) {
  const started = Date.now();
  correlationId = rec.correlation_id;
  const upn = rec.alert.user.upn ?? null;
  const hostname = rec.alert.host.hostname ?? null;
  log("triage_start", { alert_id: rec.alert.id, dedup_key: rec.dedup_key });

  let triageSection: Record<string, any>;
  let topError: string | null = null;
  try {
    const kgList = known_good_list_check(upn, hostname);
    const kgOkta = await known_good_okta_check(upn);
    const dup = await duplicate_check(rec.dedup_key);
    const results = [kgList, kgOkta, dup];
    const checks: Check[] = results.map(({ name, result, detail }) => ({ name, result, detail }));
    const kg = [kgList, kgOkta].find((c) => c.result === "match");
    const errored = results.filter((c) => c.result === "error");

    let disposition: string, reason: string;
    if (kg) {
      disposition = "DISMISS_KNOWN_GOOD"; reason = `Known-good via ${kg.name}: ${kg.detail}`;
    } else if (dup.result === "match") {
      disposition = "SUPPRESS_DUPLICATE"; reason = `Duplicate of open case ${dup.case_id}: ${dup.detail}`;
    } else if (errored.length) {
      disposition = "TRIAGE_ERROR"; reason = `Failing open: ${errored.map((c) => c.detail).join(" ")}`;
      topError = errored.map((c) => `${c.name}: ${c.detail}`).join("; ");
    } else {
      disposition = "INVESTIGATE"; reason = "No known-good or duplicate match found.";
    }
    triageSection = {
      disposition, reason,
      matched_case_id: !kg && dup.result === "match" ? dup.case_id ?? null : null,
      matched_allowlist_entry: kg?.entry ?? null,
      checks,
    };
  } catch (e) {
    topError = (e as Error).message;
    triageSection = { disposition: "TRIAGE_ERROR", reason: `Triage failed unexpectedly: ${topError}`, matched_case_id: null, matched_allowlist_entry: null, checks: [] };
  }

  const traceEntry = {
    component: COMPONENT, decision: triageSection.disposition, reason: triageSection.reason,
    duration_ms: Date.now() - started, run_url: runUrl(), error: topError,
  };
  log("triage_decision", { disposition: triageSection.disposition, reason: triageSection.reason, checks: triageSection.checks, duration_ms: traceEntry.duration_ms });
  return { ...rec, triage: triageSection, trace: [...rec.trace, traceEntry] };
}

export function httpResponse(status: number, body: unknown) {
  const text = JSON.stringify(body);
  const reasons: Record<number, string> = { 200: "OK", 400: "Bad Request", 405: "Method Not Allowed" };
  return `HTTP/1.1 ${status} ${reasons[status] ?? "OK"}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(text)}\r\n\r\n${text}`;
}

export function parseRequest(raw: string) {
  const i = raw.indexOf("\r\n\r\n");
  const head = i >= 0 ? raw.slice(0, i) : raw;
  const [method = "", target = "/"] = (head.split("\r\n")[0] ?? "").split(" ");
  return { method: method.toUpperCase(), path: target, body: i >= 0 ? raw.slice(i + 4) : "" };
}
