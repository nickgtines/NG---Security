// Appends one audit line per Enrich run to /storage/audit/YYYY-MM-DD.jsonl (space standard).
// Runs after Enrich has already responded, so the exclusive lock never delays callers.
import { appendFile, mkdir } from "node:fs/promises";
const raw = await Bun.stdin.text();
const status = Number(raw.match(/^HTTP\/\d(?:\.\d)? (\d{3})/)?.[1] ?? 0);
const sep = raw.indexOf("\r\n\r\n");
let body: any = null;
try { body = JSON.parse(sep === -1 ? raw : raw.slice(sep + 4)); } catch {}
const log = (level: string, event: string, msg: string, extra: object = {}) =>
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level, step: "Write audit record", event, msg, ...extra }) + "\n");

const ts = new Date().toISOString();
let rec: Record<string, unknown>;
if (body?.schema_version) {
  const t = body.trace?.[body.trace.length - 1] ?? {};
  const e = body.enrichment ?? {};
  rec = {
    ts, workflow: "Alert Enrichment", step: "Enrich", run_id: process.env._3B_RUN_ID ?? null,
    correlation_id: body.correlation_id, action: "alert_enriched", target: `alert:${body.alert?.id}`,
    outcome: t.decision === "ENRICHMENT_ERROR" ? "failure" : "success",
    detail: {
      decision: t.decision, duration_ms: t.duration_ms, error: t.error ?? null, ioc_summary: e.ioc_summary,
      calls: (e.ioc_results ?? []).map((r: any) => ({ provider: r.provider, ioc: r.ioc, verdict: r.verdict, cache: r.cached ? "hit" : "miss", error: r.error })),
      user_status: e.user_context?.status ?? null, host_found: e.host_context?.found ?? null,
    },
  };
} else if (body?.ioc_results) {
  rec = {
    ts, workflow: "Alert Enrichment", step: "Enrich", run_id: process.env._3B_RUN_ID ?? null, correlation_id: null,
    action: "ioc_lookup", target: `${body.ioc_type}:${body.ioc}`, outcome: "success",
    detail: { ioc_summary: body.ioc_summary, calls: body.ioc_results.map((r: any) => ({ provider: r.provider, verdict: r.verdict, cache: r.cached ? "hit" : "miss", error: r.error })) },
  };
} else {
  rec = {
    ts, workflow: "Alert Enrichment", step: "Enrich", run_id: process.env._3B_RUN_ID ?? null, correlation_id: null,
    action: "enrich_rejected", target: "request", outcome: "skipped", detail: { status, message: body?.message ?? null },
  };
}
await mkdir("/storage/audit", { recursive: true });
await appendFile(`/storage/audit/${ts.slice(0, 10)}.jsonl`, JSON.stringify(rec) + "\n");
log("info", "audit_written", "Appended audit record.", { correlation_id: rec.correlation_id, action: rec.action, outcome: rec.outcome });
