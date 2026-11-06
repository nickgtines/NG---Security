// GET /runs → 20 most recent run summaries; GET /runs?id=<correlation_id> → full stored record.
import { existsSync, readdirSync, readFileSync } from "node:fs";

const STORE = "/storage/alert-orchestrator-runs";
const raw = await Bun.stdin.text();
const target = (raw.split("\r\n")[0] ?? "").split(" ")[1] ?? "/";
const id = new URL(target, "http://x").searchParams.get("id");

function out(status: number, body: unknown) {
  const text = JSON.stringify(body);
  process.stdout.write(`HTTP/1.1 ${status} ${status === 200 ? "OK" : status === 404 ? "Not Found" : "Bad Request"}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: ${Buffer.byteLength(text)}\r\n\r\n${text}`);
}

if (id) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) out(400, { error: "id must be a correlation_id (uuid)." });
  else if (!existsSync(`${STORE}/records/${id}.json`)) out(404, { error: `No stored record for ${id}.` });
  else out(200, JSON.parse(readFileSync(`${STORE}/records/${id}.json`, "utf8")));
} else {
  const dir = `${STORE}/index`;
  const names = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".json")).sort().reverse().slice(0, 20) : [];
  out(200, { runs: names.map((n) => JSON.parse(readFileSync(`${dir}/${n}`, "utf8"))) });
}
