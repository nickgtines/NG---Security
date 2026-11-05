import { randomUUID } from "node:crypto";
import { OPEN_DIR, Reachout, httpResponse, log, parseHttp, writeJson } from "./lib.ts";

const raw = await Bun.stdin.text();
const req = parseHttp(raw);
const [method] = req.startLine.split(" ");

function reply(status: number, reason: string, body: unknown) {
  process.stdout.write(httpResponse(status, reason, JSON.stringify(body)));
}

if (method !== "POST") {
  log(null, "rejected_method", { method });
  reply(405, "Method Not Allowed", { error: "Use POST" });
  process.exit(0);
}

let input: any;
try {
  input = JSON.parse(req.body || "");
} catch {
  log(null, "rejected_invalid_json");
  reply(400, "Bad Request", { error: "Body must be JSON" });
  process.exit(0);
}

const cid = typeof input?.correlation_id === "string" ? input.correlation_id.trim() : null;
const errors: string[] = [];
const str = (k: string, max: number) => {
  const v = input?.[k];
  if (typeof v !== "string" || !v.trim()) errors.push(`${k} is required`);
  else if (v.length > max) errors.push(`${k} must be at most ${max} characters`);
  return typeof v === "string" ? v.trim() : "";
};

if (typeof input !== "object" || input === null || Array.isArray(input)) errors.push("Body must be a JSON object");
const correlation_id = str("correlation_id", 200);
const caseRaw = input?.case_id;
const case_id = typeof caseRaw === "number" ? String(caseRaw) : typeof caseRaw === "string" ? caseRaw.trim() : "";
if (!/^\d{1,18}$/.test(case_id)) errors.push("case_id must be a numeric case ID");
const case_url = str("case_url", 2000);
if (case_url && !/^https:\/\/\S+$/.test(case_url)) errors.push("case_url must be an https URL");
const user_upn = str("user_upn", 320).toLowerCase();
if (user_upn && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user_upn)) errors.push("user_upn must be an email address");
const question = str("question", 2000);
const alert_title = str("alert_title", 500);
const slack_channel = str("slack_channel", 50);
if (slack_channel && !/^[CGD][A-Z0-9]{6,}$/.test(slack_channel)) errors.push("slack_channel must be a Slack channel ID");
const slack_thread_ts = str("slack_thread_ts", 30);
if (slack_thread_ts && !/^\d{9,11}\.\d{1,6}$/.test(slack_thread_ts)) errors.push("slack_thread_ts must be a Slack message ts");
let timeout_minutes = 60;
if (input?.timeout_minutes !== undefined && input?.timeout_minutes !== null) {
  const t = Number(input.timeout_minutes);
  if (!Number.isInteger(t) || t < 1 || t > 10080) errors.push("timeout_minutes must be an integer from 1 to 10080");
  else timeout_minutes = t;
}

if (errors.length) {
  log(cid, "rejected_validation", { errors });
  reply(400, "Bad Request", { error: "Invalid input", details: errors });
  process.exit(0);
}

const now = new Date();
const reachout_id = randomUUID();
const record: Reachout = {
  reachout_id,
  correlation_id,
  case_id,
  case_url,
  user_upn,
  question,
  alert_title,
  slack_channel,
  slack_thread_ts,
  timeout_minutes,
  created_at: now.toISOString(),
  deadline_at: new Date(now.getTime() + timeout_minutes * 60_000).toISOString(),
  status: "pending",
};
writeJson(`${OPEN_DIR}/${reachout_id}.json`, record);
log(correlation_id, "reachout_accepted", { reachout_id, case_id, timeout_minutes });
reply(202, "Accepted", { reachout_id });
