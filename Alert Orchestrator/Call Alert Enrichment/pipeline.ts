// Shared helpers for the Call Alert * steps (identical copy in each step).
// Each step reads the envelope from stdin, maybe calls its component, and writes the envelope on.
// Envelope: { kind: "record" | "invalid", source, ingest_ms, started_at, record, exchanges, error?, status?, trace? }

export const COMPONENT = "alert-orchestrator";
export const CALL_TIMEOUT_MS = 30_000;
const BASE = (process.env.WORKFLOW_URL ?? "").replace(/\/+$/, "");
export type Rec = Record<string, any>;
export const runUrl = () => process.env._3B_RUN_URL || null;

let cid: string | null = null;
export const log = (event: string, data: Record<string, unknown> = {}) =>
  console.error(JSON.stringify({ ts: new Date().toISOString(), component: COMPONENT, correlation_id: cid, run_id: process.env._3B_RUN_ID ?? null, event, ...data }));

export async function readEnvelope(): Promise<Rec> {
  const env = JSON.parse(await Bun.stdin.text());
  cid = env.correlation_id ?? env.record?.correlation_id ?? null;
  env.exchanges ??= [];
  return env;
}
export const pass = (env: Rec) => process.stdout.write(JSON.stringify(env));

// Compact view for logs (stderr keeps 10 KiB); the full record is stored by Call Alert Response.
const brief = (r: Rec) => JSON.stringify({
  alert_id: r?.alert?.id, dedup_key: r?.dedup_key, case: r?.case,
  triage: r?.triage && { disposition: r.triage.disposition, reason: r.triage.reason, matched_case_id: r.triage.matched_case_id },
  enrichment: r?.enrichment && { ioc_summary: r.enrichment.ioc_summary, user: r.enrichment.user_context?.status ?? null, host_found: r.enrichment.host_context?.found ?? null },
  investigation: r?.investigation && { verdict: r.investigation.verdict, risk_score: r.investigation.risk_score }, response: r?.response, trace_len: r?.trace?.length,
}).slice(0, 900);

// Calls one component through its workflow connector. On failure/timeout keeps the last good
// record and appends a call_failed trace entry so the pipeline carries on.
export async function call(env: Rec, component: string, path: string): Promise<void> {
  const record = env.record;
  const started = Date.now();
  const body = JSON.stringify(record);
  log("component_request", { target: component, path, payload: brief(record), bytes: body.length });
  let status: number | null = null;
  try {
    const r = await fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(CALL_TIMEOUT_MS) });
    status = r.status;
    const text = await r.text();
    let out: Rec | null = null;
    try { out = JSON.parse(text); } catch { /* handled below */ }
    log("component_response", { target: component, status, payload: out ? brief(out) : text.slice(0, 500), bytes: text.length, duration_ms: Date.now() - started });
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.slice(0, 300)}`);
    if (out?.correlation_id !== record.correlation_id || !Array.isArray(out?.trace)) throw new Error("response is not the alert record");
    env.exchanges.push({ component, path, status, duration_ms: Date.now() - started, error: null });
    env.record = out;
  } catch (e) {
    const err = (e as Error).name === "TimeoutError" ? `timed out after ${CALL_TIMEOUT_MS / 1000}s` : (e as Error).message;
    log("component_failed", { target: component, status, error: err });
    env.exchanges.push({ component, path, status, duration_ms: Date.now() - started, error: err });
    record.trace.push({ component, decision: "call_failed", reason: `${component} call failed; kept last good record.`, duration_ms: Date.now() - started, run_url: null, error: err });
  }
}

// Routing rule: which dispositions go through enrichment + investigation.
export const needsInvestigation = (r: Rec) => !["SUPPRESS_DUPLICATE", "DISMISS_KNOWN_GOOD"].includes(r?.triage?.disposition);
