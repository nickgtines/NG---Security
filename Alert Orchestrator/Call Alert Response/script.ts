// Step 4: record = Alert Response (POST /respond), always. Then append the Orchestrator's trace
// entry, store the final record by correlation_id, and answer the ingest HTTP request.
import { mkdirSync, writeFileSync } from "node:fs";
import { readEnvelope, call, log, needsInvestigation, runUrl, COMPONENT, type Rec } from "./pipeline";

const STORE = "/storage/alert-orchestrator-runs";

function store(id: string, status: number, doc: Rec) {
  const at = new Date().toISOString();
  mkdirSync(`${STORE}/records`, { recursive: true });
  mkdirSync(`${STORE}/index`, { recursive: true });
  writeFileSync(`${STORE}/records/${id}.json`, JSON.stringify({ stored_at: at, http_status: status, ...doc }));
  const r = doc.record;
  writeFileSync(`${STORE}/index/${at.replace(/[:.]/g, "-")}_${id}.json`, JSON.stringify({
    correlation_id: id, stored_at: at, http_status: status, source: doc.source ?? r?.alert?.source ?? null,
    title: r?.alert?.title ?? doc.error ?? null, disposition: r?.triage?.disposition ?? null,
    verdict: r?.investigation?.verdict ?? null, case_url: r?.case?.url ?? null,
  }));
}

function respond(status: number, body: unknown) {
  const text = JSON.stringify(body);
  const reason: Record<number, string> = { 200: "OK", 400: "Bad Request", 405: "Method Not Allowed" };
  process.stdout.write(`HTTP/1.1 ${status} ${reason[status] ?? "OK"}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(text)}\r\n\r\n${text}`);
}

const env = await readEnvelope();
if (env.kind === "invalid") {
  log("invalid_input", { source: env.source, error: env.error });
  store(env.correlation_id, env.status, { source: env.source, error: env.error, trace: env.trace, record: null, exchanges: [] });
  respond(env.status, { error: env.error, correlation_id: env.correlation_id, trace: env.trace });
} else {
  // Response needs a triage section; if Triage was unreachable, fail open so a case is still created.
  if (!env.record.triage) env.record.triage = { disposition: "TRIAGE_ERROR", reason: "Alert Triage did not return a result; failing open.", matched_case_id: null, matched_allowlist_entry: null, checks: [] };
  await call(env, "Alert Response", "/respond");
  const r = env.record;
  const full = needsInvestigation(r);
  const errors = r.trace.filter((t: Rec) => t.decision === "call_failed").map((t: Rec) => `${t.component}: ${t.error}`);
  r.trace.push({
    component: COMPONENT,
    decision: full ? "triage → enrichment → investigation → response" : "triage → response",
    reason: full ? `${r.triage.disposition}: full investigation; verdict ${r.investigation?.verdict ?? "unavailable"}.` : `${r.triage.disposition}: no enrichment or investigation needed.`,
    duration_ms: Date.now() - (env.started_at ?? Date.now()), run_url: runUrl(), error: errors.join("; ") || null,
  });
  log("orchestration_done", { route: r.trace.at(-1).decision, case: r.case, actions: r.response?.actions ?? [] });
  store(r.correlation_id, 200, { source: env.source, record: r, exchanges: env.exchanges });
  respond(200, r);
}
