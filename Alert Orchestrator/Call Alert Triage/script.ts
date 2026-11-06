// Step 1: record = Alert Triage (POST /triage). Invalid ingest input passes straight through.
import { readEnvelope, call, pass, log } from "./pipeline";
const env = await readEnvelope();
if (env.kind === "record") {
  env.started_at = Date.now();
  env.record.trace.push({ component: "alert-orchestrator.ingest", decision: "normalized", reason: `${env.source} payload normalized to contract v3 (${env.record.alert.iocs.ips.length} IPs, ${env.record.alert.iocs.domains.length} domains, ${env.record.alert.iocs.hashes.length} hashes).`, duration_ms: env.ingest_ms ?? 0, run_url: process.env._3B_RUN_URL || null, error: null });
  await call(env, "Alert Triage", "/triage");
  log("triage_done", { disposition: env.record.triage?.disposition ?? null });
}
pass(env);
