// Runs the bundled sample record (or a POSTed record) through the same triage logic as POST /triage.
import { triage, validate, ContractError, httpResponse, parseRequest } from "./triage.ts";
import { createHash } from "node:crypto";
import sample from "./sample.json";

const req = parseRequest(await Bun.stdin.text());
let rec: any = sample;
if (req.method === "POST" && req.body.trim()) {
  try { rec = JSON.parse(req.body); } catch (e) {
    process.stdout.write(httpResponse(400, { error: `Body is not valid JSON: ${(e as Error).message}` })); process.exit(0);
  }
} else {
  rec = structuredClone(sample);
  const a = rec.alert;
  rec.dedup_key = createHash("sha256").update(`${a.rule_name}|${a.user.upn ?? ""}|${a.host.hostname ?? ""}`.toLowerCase()).digest("hex");
}
try { validate(rec); } catch (e) {
  if (e instanceof ContractError) { process.stdout.write(httpResponse(400, { error: e.message })); process.exit(0); }
  throw e;
}
process.stdout.write(httpResponse(200, await triage(rec)));
