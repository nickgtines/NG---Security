// Known-good list API: GET list, POST add, DELETE ?id=<id> remove.
// One file per entry so concurrent edits never touch the same file.
import { mkdirSync, readdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";

const ROOT = "/storage/known-good";
const DIR = `${ROOT}/entries`;
const SEEDED = `${ROOT}/.seeded`;
const TYPES = ["service_account", "scanner", "break_glass", "host"];
const SEEDS = [
  { id: "seed-svc-backup", type: "service_account", value: "svc-backup@contoso.com", reason: "Nightly backup service account", owner: "it-ops@contoso.com", expires_at: null },
  { id: "seed-vulnscan01", type: "scanner", value: "VULNSCAN01", reason: "Authorized vulnerability scanner", owner: "secops@contoso.com", expires_at: null },
];

const raw = await Bun.stdin.text();
const i = raw.indexOf("\r\n\r\n");
const head = i >= 0 ? raw.slice(0, i) : raw;
const body = i >= 0 ? raw.slice(i + 4) : "";
const [method, target = "/"] = head.split("\r\n")[0].split(" ");
const actor = head.match(/^x-3b-authenticated-email:\s*(.+)$/im)?.[1]?.trim() ?? "unknown";
const url = new URL(target, "http://x");

const log = (event: string, d: Record<string, unknown> = {}) =>
  console.error(JSON.stringify({ ts: new Date().toISOString(), component: "known-good-api", correlation_id: null, actor, event, ...d }));

function respond(status: number, payload: unknown) {
  const t = JSON.stringify(payload);
  process.stdout.write(`HTTP/1.1 ${status} X\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(t)}\r\n\r\n${t}`);
  process.exit(0);
}

if (!existsSync(SEEDED)) {
  mkdirSync(DIR, { recursive: true });
  for (const s of SEEDS) if (!existsSync(`${DIR}/${s.id}.json`)) writeFileSync(`${DIR}/${s.id}.json`, JSON.stringify(s, null, 2));
  writeFileSync(SEEDED, new Date().toISOString());
  log("seeded", { count: SEEDS.length });
}
const list = () => readdirSync(DIR).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(readFileSync(`${DIR}/${f}`, "utf8")))
  .sort((a, b) => String(a.value).localeCompare(String(b.value)));

if (method === "GET") respond(200, { entries: list() });

if (method === "POST") {
  let e: any;
  try { e = JSON.parse(body); } catch { respond(400, { error: "Body must be JSON." }); }
  const errs: string[] = [];
  if (!TYPES.includes(e?.type)) errs.push(`type must be one of ${TYPES.join(", ")}`);
  for (const k of ["value", "reason", "owner"]) if (typeof e?.[k] !== "string" || !e[k].trim()) errs.push(`${k} is required`);
  if (e?.expires_at != null && e.expires_at !== "" && isNaN(Date.parse(e.expires_at))) errs.push("expires_at must be ISO 8601 or empty");
  if (errs.length) respond(400, { error: errs.join("; ") });
  if (list().some((x) => String(x.value).toLowerCase() === e.value.trim().toLowerCase())) respond(400, { error: `An entry for ${e.value} already exists.` });
  const entry = { id: randomUUID(), type: e.type, value: e.value.trim(), reason: e.reason.trim(), owner: e.owner.trim(),
    expires_at: e.expires_at ? new Date(e.expires_at).toISOString() : null, added_by: actor, added_at: new Date().toISOString() };
  writeFileSync(`${DIR}/${entry.id}.json`, JSON.stringify(entry, null, 2));
  log("entry_added", { entry });
  respond(200, { entry });
}

if (method === "DELETE") {
  const id = url.searchParams.get("id") ?? "";
  if (!/^[A-Za-z0-9-]+$/.test(id) || !existsSync(`${DIR}/${id}.json`)) respond(400, { error: "Unknown entry id." });
  const old = JSON.parse(readFileSync(`${DIR}/${id}.json`, "utf8"));
  rmSync(`${DIR}/${id}.json`);
  log("entry_removed", { entry: old });
  respond(200, { removed: id });
}

respond(405, { error: "Use GET, POST or DELETE." });
