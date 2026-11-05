// Shared helpers for Security Reachout. Copied verbatim into each step that needs them.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";

export const STORE = "/storage/reachouts";
export const OPEN_DIR = `${STORE}/open`;
export const RESPONSES_DIR = `${STORE}/responses`;
export const CLOSED_DIR = `${STORE}/closed`;

export type Answer = "confirmed" | "denied" | "no_response";

export interface Reachout {
  reachout_id: string;
  correlation_id: string;
  case_id: string;
  case_url: string;
  user_upn: string;
  question: string;
  alert_title: string;
  slack_channel: string;
  slack_thread_ts: string;
  timeout_minutes: number;
  created_at: string;
  deadline_at: string;
  status: "pending" | "sent" | "closed";
  slack_user_id?: string;
  dm_channel?: string;
  dm_ts?: string;
  sent_at?: string;
  outcome?: Answer | "user_not_found";
  closed_at?: string;
}

export interface ResponseRecord {
  reachout_id: string;
  answer: "confirmed" | "denied";
  slack_user_id: string;
  responded_at: string;
}

/** One JSON line on stderr; correlation_id is always present. */
export function log(correlationId: string | null | undefined, event: string, extra: Record<string, unknown> = {}) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), correlation_id: correlationId ?? null, event, ...extra }));
}

export const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function readJson<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export function writeJson(path: string, value: unknown) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2));
  renameSync(tmp, path);
}

export function removeIfExists(path: string) {
  if (existsSync(path)) unlinkSync(path);
}

export interface HttpMessage {
  startLine: string;
  headers: Record<string, string>;
  body: string;
}

export function parseHttp(raw: string): HttpMessage {
  const sep = raw.indexOf("\r\n\r\n");
  const head = sep === -1 ? raw : raw.slice(0, sep);
  const body = sep === -1 ? "" : raw.slice(sep + 4);
  const [startLine, ...lines] = head.split("\r\n");
  const headers: Record<string, string> = {};
  for (const line of lines) {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return { startLine: startLine ?? "", headers, body };
}

export function httpResponse(status: number, reason: string, body = "", headers: Record<string, string> = {}): string {
  const all: Record<string, string> = { "content-length": String(Buffer.byteLength(body)), ...headers };
  if (body && !all["content-type"]) all["content-type"] = "application/json";
  const lines = Object.entries(all).map(([k, v]) => `${k}: ${v}`);
  return `HTTP/1.1 ${status} ${reason}\r\n${lines.join("\r\n")}\r\n\r\n${body}`;
}

/** Escape text for Slack mrkdwn. */
export function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export class SlackApiError extends Error {
  constructor(public method: string, public code: string) {
    super(`Slack ${method} failed: ${code}`);
  }
}

export async function slack(method: string, body: Record<string, unknown>, cid: string): Promise<any> {
  const res = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new SlackApiError(method, `http_${res.status}`);
  const json: any = await res.json();
  if (!json.ok) {
    log(cid, "slack_api_error", { method, error: json.error });
    throw new SlackApiError(method, String(json.error));
  }
  log(cid, "slack_api_ok", { method });
  return json;
}

export async function tines(method: string, path: string, cid: string, body?: unknown): Promise<any> {
  const base = process.env.TINES_URL;
  if (!base) throw new Error("TINES_URL is not set; attach the Tines connector to this step");
  const res = await fetch(`${base.replace(/\/$/, "")}${path}`, {
    method,
    headers: { "content-type": "application/json", accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    log(cid, "tines_api_error", { method, path, status: res.status, body: text.slice(0, 500) });
    throw new Error(`Tines ${method} ${path} failed with ${res.status}`);
  }
  log(cid, "tines_api_ok", { method, path, status: res.status });
  return text ? JSON.parse(text) : null;
}

export async function commentOnCase(rec: Reachout, value: string) {
  await tines("POST", `/api/v2/cases/${encodeURIComponent(rec.case_id)}/comments`, rec.correlation_id, { value });
}

export async function threadReply(rec: Reachout, text: string) {
  await slack(
    "chat.postMessage",
    { channel: rec.slack_channel, thread_ts: rec.slack_thread_ts, text, unfurl_links: false },
    rec.correlation_id,
  );
}

/** Move a record to closed/ and drop its open/ and responses/ files. */
export function closeRecord(rec: Reachout, outcome: Reachout["outcome"]) {
  const closed: Reachout = { ...rec, status: "closed", outcome, closed_at: new Date().toISOString() };
  writeJson(`${CLOSED_DIR}/${rec.reachout_id}.json`, closed);
  removeIfExists(`${OPEN_DIR}/${rec.reachout_id}.json`);
  removeIfExists(`${RESPONSES_DIR}/${rec.reachout_id}.json`);
  log(rec.correlation_id, "reachout_closed", { reachout_id: rec.reachout_id, outcome });
}
