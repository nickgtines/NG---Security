// Read-only entity context. These functions only issue GET requests.
// lookup_crowdstrike_host never contains a host or performs any other action.
import { CONFIG } from "./config";
import { CallError, ensureOk, fetchJson, log, maskUpn } from "./lib";

function baseUrl(v: string | undefined, name: string) {
  if (!v) throw new CallError(`${name} is not set; is the connector attached?`);
  return (/^https?:\/\//.test(v) ? v : `https://${v}`).replace(/\/+$/, "");
}
function errMsg(e: unknown) {
  return e instanceof CallError ? e.message : `error: ${(e as any)?.message ?? String(e)}`;
}

// ---------------------------------------------------------------- Okta
export async function lookup_okta_user(upn: string) {
  const t0 = performance.now();
  const ctx = {
    provider: "okta" as const,
    status: "UNKNOWN",
    groups: [] as string[],
    mfa_factors: [] as string[],
    last_login: null as string | null,
    recent_logins: [] as { time: string; ip: string; country: string }[],
    error: null as string | null,
  };
  const errors: string[] = [];
  const call = async (what: string, url: string, allowed: number[] = []) => {
    const r = await fetchJson(url);
    log("info", "provider_call", `Okta ${what} returned ${r.status}.`, { provider: "okta", call: what, user: maskUpn(upn), status: r.status, latency_ms: r.ms, cache: "n/a" });
    ensureOk(r, allowed);
    return r;
  };
  try {
    const base = baseUrl(process.env.OKTA_ORG_URL ?? process.env.OKTA_DOMAIN, "OKTA_ORG_URL");
    const u = await call("user", `${base}/api/v1/users/${encodeURIComponent(upn)}`, [404]);
    if (u.status === 404) {
      ctx.status = "NOT_FOUND";
    } else {
      const user = u.json;
      ctx.status = user.status ?? "UNKNOWN";
      ctx.last_login = user.lastLogin ?? null;
      const id = encodeURIComponent(user.id);
      const since = new Date(Date.now() - CONFIG.OKTA.LOG_LOOKBACK_DAYS * 86400_000).toISOString();
      const filter = `actor.alternateId eq "${upn.replace(/["\\]/g, "")}" and eventType eq "user.session.start"`;
      const logsQ = new URLSearchParams({ filter, since, sortOrder: "DESCENDING", limit: String(CONFIG.OKTA.RECENT_LOGINS) });
      const [g, f, l] = await Promise.allSettled([
        call("groups", `${base}/api/v1/users/${id}/groups`),
        call("factors", `${base}/api/v1/users/${id}/factors`),
        call("system_log", `${base}/api/v1/logs?${logsQ}`),
      ]);
      if (g.status === "fulfilled") ctx.groups = (g.value.json ?? []).map((x: any) => x?.profile?.name).filter(Boolean);
      else errors.push(`groups: ${errMsg(g.reason)}`);
      if (f.status === "fulfilled") ctx.mfa_factors = [...new Set<string>((f.value.json ?? []).map((x: any) => x?.factorType).filter(Boolean))];
      else errors.push(`factors: ${errMsg(f.reason)}`);
      if (l.status === "fulfilled") {
        ctx.recent_logins = (l.value.json ?? []).slice(0, CONFIG.OKTA.RECENT_LOGINS).map((e: any) => ({
          time: e?.published ?? "",
          ip: e?.client?.ipAddress ?? "",
          country: e?.client?.geographicalContext?.country ?? "",
        }));
      } else errors.push(`system_log: ${errMsg(l.reason)}`);
    }
  } catch (e) {
    errors.push(errMsg(e));
  }
  ctx.error = errors.length ? errors.join("; ") : null;
  log(ctx.error ? "warn" : "info", "entity_lookup", "Okta user context complete.", {
    provider: "okta", ioc: maskUpn(upn), verdict: ctx.status, latency_ms: Math.round(performance.now() - t0), cache: "n/a", error: ctx.error,
  });
  return ctx;
}

// ---------------------------------------------------------------- CrowdStrike
export async function lookup_crowdstrike_host(hostname: string | null, device_id: string | null) {
  const t0 = performance.now();
  const ctx = {
    provider: "crowdstrike" as const,
    found: false,
    hostname: null as string | null,
    device_id: null as string | null,
    platform: null as string | null,
    last_seen: null as string | null,
    sensor_version: null as string | null,
    tags: [] as string[],
    containment_status: null as string | null,
    error: null as string | null,
  };
  const call = async (what: string, url: string) => {
    const r = await fetchJson(url); // GET only
    log("info", "provider_call", `CrowdStrike ${what} returned ${r.status}.`, { provider: "crowdstrike", call: what, ioc: hostname ?? device_id, status: r.status, latency_ms: r.ms, cache: "n/a" });
    ensureOk(r, [404]);
    return r;
  };
  try {
    const base = baseUrl(process.env.CROWD_STRIKE_URL, "CROWD_STRIKE_URL");
    let aid: string | null = device_id && /^[a-f0-9]{32}$/i.test(device_id) ? device_id.toLowerCase() : null;
    let dev: any = null;
    const details = async (id: string) => (await call("device_details", `${base}/devices/entities/devices/v2?ids=${encodeURIComponent(id)}`)).json?.resources?.[0] ?? null;
    if (aid) dev = await details(aid);
    if (!dev && hostname) {
      // Falcon stores the short hostname; strip any domain suffix (FQDN trap).
      const short = hostname.split(".")[0].replace(/['\\]/g, "");
      const q = new URLSearchParams({ filter: `hostname:'${short}'`, sort: "last_seen.desc", limit: "1" });
      const ids = (await call("device_query", `${base}/devices/queries/devices/v1?${q}`)).json?.resources ?? [];
      if (ids[0]) dev = await details(ids[0]);
    }
    if (dev) {
      ctx.found = true;
      ctx.hostname = dev.hostname ?? null;
      ctx.device_id = dev.device_id ?? null;
      ctx.platform = dev.platform_name ?? null;
      ctx.last_seen = dev.last_seen ?? null;
      ctx.sensor_version = dev.agent_version ?? null;
      ctx.tags = Array.isArray(dev.tags) ? dev.tags : [];
      ctx.containment_status = dev.status ?? null;
    }
  } catch (e) {
    ctx.error = errMsg(e);
  }
  log(ctx.error ? "warn" : "info", "entity_lookup", "CrowdStrike host context complete.", {
    provider: "crowdstrike", ioc: hostname ?? device_id, verdict: ctx.found ? "found" : "not_found", latency_ms: Math.round(performance.now() - t0), cache: "n/a", error: ctx.error,
  });
  return ctx;
}
