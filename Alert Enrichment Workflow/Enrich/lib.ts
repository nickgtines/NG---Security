import { createHash, randomUUID } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { CONFIG } from "./config";

// ---------------------------------------------------------------- types
export type IocType = "ip" | "domain" | "url" | "hash";
export type Provider = "greynoise" | "abuseipdb" | "virustotal" | "urlscan";
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";
export interface IocResult {
  ioc: string;
  ioc_type: IocType;
  provider: Provider;
  verdict: Verdict;
  score: number | null;
  details: Record<string, unknown>;
  cached: boolean;
  error: string | null;
}

// ---------------------------------------------------------------- logging
// One JSON object per line on stderr. Every line carries correlation_id.
const logCtx: Record<string, unknown> = { correlation_id: null };
export function setLogContext(c: Record<string, unknown>) {
  Object.assign(logCtx, c);
}
export function log(level: "debug" | "info" | "warn" | "error", event: string, msg: string, extra: Record<string, unknown> = {}) {
  process.stderr.write(
    JSON.stringify({ ts: new Date().toISOString(), level, step: "Enrich", event, msg, ...logCtx, ...extra }) + "\n",
  );
}
/** Mask a UPN for logs: "j***@example.com". */
export function maskUpn(upn: string): string {
  const [local, domain] = upn.split("@");
  return `${(local ?? "").slice(0, 1)}***${domain ? "@" + domain : ""}`;
}

// ---------------------------------------------------------------- HTTP
export class CallError extends Error {
  constructor(message: string, public status: number | null = null) {
    super(message);
  }
}
export interface HttpResult {
  status: number;
  json: any;
  ms: number;
}
/** fetch with the per-call timeout; never throws for HTTP status, only for transport/timeout. */
export async function fetchJson(url: string, init: RequestInit = {}): Promise<HttpResult> {
  const t0 = performance.now();
  try {
    const res = await fetch(url, {
      ...init,
      headers: { accept: "application/json", ...(init.headers ?? {}) },
      signal: AbortSignal.timeout(CONFIG.CALL_TIMEOUT_MS),
    });
    const text = await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { non_json_body_prefix: text.slice(0, 200) };
    }
    return { status: res.status, json, ms: Math.round(performance.now() - t0) };
  } catch (e: any) {
    if (e?.name === "TimeoutError" || e?.name === "AbortError") {
      throw new CallError(`timeout after ${CONFIG.CALL_TIMEOUT_MS}ms`);
    }
    throw new CallError(`network error: ${e?.message ?? String(e)}`);
  }
}
/** Throw a CallError for 429 and other non-success statuses (except those listed as allowed). */
export function ensureOk(r: HttpResult, allowed: number[] = []) {
  if (r.status >= 200 && r.status < 300) return;
  if (allowed.includes(r.status)) return;
  if (r.status === 429) throw new CallError("rate limited (429)", 429);
  const hint = r.json?.message ?? r.json?.error?.message ?? r.json?.errors?.[0]?.detail ?? r.json?.errors?.[0]?.message ?? r.json?.errorSummary ?? "";
  throw new CallError(`HTTP ${r.status}${hint ? `: ${String(hint).slice(0, 160)}` : ""}`, r.status);
}

// ---------------------------------------------------------------- concurrency
export function limiter(max: number) {
  let active = 0;
  const queue: (() => void)[] = [];
  return async function run<T>(fn: () => Promise<T>): Promise<T> {
    if (active >= max) await new Promise<void>((r) => queue.push(r));
    active++;
    try {
      return await fn();
    } finally {
      active--;
      queue.shift()?.();
    }
  };
}

// ---------------------------------------------------------------- cache
// Layout: /storage/ioc-cache/<provider>/<sha256(ioc)>/<epochMs>-<uuid>.json
// Request runs only ever create new uniquely named files, so overlapping runs never
// touch the same file. The scheduled "Cache cleanup" step deletes expired entries.
const CACHE_ROOT = "/storage/ioc-cache";
const TTL_MS = CONFIG.CACHE_TTL_HOURS * 3600_000;

function cacheKey(provider: Provider, ioc: string, type: IocType) {
  const norm = type === "url" ? ioc : ioc.toLowerCase();
  return `${CACHE_ROOT}/${provider}/${createHash("sha256").update(`${provider}|${norm}`).digest("hex")}`;
}
export async function cacheGet(provider: Provider, ioc: string, type: IocType): Promise<IocResult | null> {
  const dir = cacheKey(provider, ioc, type);
  let names: string[];
  try {
    names = (await readdir(dir)).filter((n) => n.endsWith(".json"));
  } catch {
    return null; // no entry
  }
  const newest = names.map((n) => ({ n, t: Number(n.split("-")[0]) })).filter((x) => Number.isFinite(x.t)).sort((a, b) => b.t - a.t)[0];
  if (!newest || Date.now() - newest.t > TTL_MS) return null;
  try {
    const entry = JSON.parse(await readFile(`${dir}/${newest.n}`, "utf8")) as IocResult;
    return { ...entry, cached: true };
  } catch (e: any) {
    log("warn", "cache_read_failed", "Could not read a cache entry; treating as a miss.", { provider, error: e?.message });
    return null;
  }
}
export async function cachePut(r: IocResult): Promise<void> {
  if (r.error) return; // never cache errors
  try {
    const dir = cacheKey(r.provider, r.ioc, r.ioc_type);
    await mkdir(dir, { recursive: true });
    await writeFile(`${dir}/${Date.now()}-${randomUUID()}.json`, JSON.stringify({ ...r, cached: false }));
  } catch (e: any) {
    log("warn", "cache_write_failed", "Could not write a cache entry; continuing.", { provider: r.provider, error: e?.message });
  }
}

// ---------------------------------------------------------------- IOC helpers
/** True for RFC1918/unique-local, loopback, link-local (and unspecified) addresses. */
export function isNonRoutableIp(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === "::1" || s === "::") return true;
    if (/^fe[89ab]/.test(s)) return true; // fe80::/10 link-local
    if (/^f[cd]/.test(s)) return true; // fc00::/7 unique local
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isNonRoutableIp(mapped[1]);
  }
  return false;
}
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$/i;
const HASH_LEN: Record<number, "md5" | "sha1" | "sha256"> = { 32: "md5", 40: "sha1", 64: "sha256" };

export function isDomain(s: string) {
  return DOMAIN_RE.test(s);
}
export function isUrl(s: string) {
  try {
    const u = new URL(s);
    return (u.protocol === "http:" || u.protocol === "https:") && !!u.hostname;
  } catch {
    return false;
  }
}
export function hashTypeOf(s: string) {
  return /^[a-f0-9]+$/i.test(s) ? HASH_LEN[s.length] ?? null : null;
}
/** Auto-detect an IOC's type; null when it isn't recognisable. */
export function detectIocType(raw: string): { ioc: string; ioc_type: IocType; hash_type?: string } | null {
  const s = raw.trim();
  if (!s) return null;
  if (isIP(s)) return { ioc: s, ioc_type: "ip" };
  const h = hashTypeOf(s);
  if (h) return { ioc: s.toLowerCase(), ioc_type: "hash", hash_type: h };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return isUrl(s) ? { ioc: s, ioc_type: "url" } : null;
  const d = s.toLowerCase().replace(/\.$/, "");
  if (isDomain(d)) return { ioc: d, ioc_type: "domain" };
  return null;
}
