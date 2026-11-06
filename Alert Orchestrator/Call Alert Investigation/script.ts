// Step 3: INVESTIGATE / TRIAGE_ERROR → record = Alert Investigation (POST /investigate). Otherwise skip.
import { readEnvelope, call, pass, log, needsInvestigation } from "./pipeline";
const env = await readEnvelope();
if (env.kind === "record" && needsInvestigation(env.record)) await call(env, "Alert Investigation", "/investigate");
else log("investigation_skipped", { disposition: env.record?.triage?.disposition ?? null, kind: env.kind });
pass(env);
