// Hourly: delete IOC cache entries older than the TTL (and superseded entries), then empty dirs.
// Only this step deletes; Enrich only creates new uniquely-named files, so writers never collide.
import { readdir, rm, rmdir } from "node:fs/promises";
const TTL_HOURS = 24; // keep in sync with Enrich/config.ts CACHE_TTL_HOURS
const ROOT = "/storage/ioc-cache";
const MAX_DELETES = 20000; // per-run bound
const log = (level: string, event: string, msg: string, extra: object = {}) =>
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level, step: "Cache cleanup", event, msg, correlation_id: null, ...extra }) + "\n");
const ls = async (p: string) => { try { return await readdir(p); } catch { return []; } };
log("info", "cleanup_started", "Cleaning expired IOC cache entries.");
const cutoff = Date.now() - TTL_HOURS * 3600_000;
let deleted = 0, kept = 0;
outer: for (const provider of await ls(ROOT)) {
  for (const key of await ls(`${ROOT}/${provider}`)) {
    const dir = `${ROOT}/${provider}/${key}`;
    const files = (await ls(dir)).map((n) => ({ n, t: Number(n.split("-")[0]) })).sort((a, b) => b.t - a.t);
    for (const [i, f] of files.entries()) {
      if (i === 0 && f.t >= cutoff) { kept++; continue; } // newest, still fresh
      await rm(`${dir}/${f.n}`, { force: true });
      if (++deleted >= MAX_DELETES) break outer;
    }
    if (files.length && files[0].t < cutoff) await rmdir(dir).catch(() => {});
  }
}
log("info", "cleanup_completed", "Cache cleanup finished.", { deleted, kept });
