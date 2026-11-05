import { triage, validate, ContractError, httpResponse, parseRequest, log } from "./triage.ts";

const raw = await Bun.stdin.text();
const req = parseRequest(raw);

if (req.method !== "POST") {
  process.stdout.write(httpResponse(405, { error: "Use POST /triage with an alert record (schema_version 3)." }));
} else {
  let rec: unknown;
  try {
    rec = JSON.parse(req.body);
    validate(rec);
  } catch (e) {
    const msg = e instanceof ContractError ? e.message : `Body is not valid JSON: ${(e as Error).message}`;
    log("contract_rejected", { error: msg });
    process.stdout.write(httpResponse(400, { error: msg }));
    process.exit(0);
  }
  process.stdout.write(httpResponse(200, await triage(rec as Record<string, any>)));
}
