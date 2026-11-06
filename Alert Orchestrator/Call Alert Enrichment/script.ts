// Step 2: INVESTIGATE / TRIAGE_ERROR → record = Alert Enrichment (POST /enrich). Otherwise skip.
import { readEnvelope, call, pass, log, needsInvestigation } from "./pipeline";
const env = await readEnvelope();
if (env.kind === "record" && needsInvestigation(env.record)) await call(env, "Alert Enrichment", "/enrich");
else log("enrichment_skipped", { disposition: env.record?.triage?.disposition ?? null, kind: env.kind });
pass(env);
