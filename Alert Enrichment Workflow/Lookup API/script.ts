// Backend for the /lookup page. Forwards {"ioc": "..."} to Enrich as a single-IOC lookup;
// Enrich detects the type, validates it and returns the per-provider results.
const raw = await Bun.stdin.text();
const sep = raw.indexOf("\r\n\r\n");
let ioc: unknown = null;
try { ioc = JSON.parse(sep === -1 ? "" : raw.slice(sep + 4))?.ioc ?? null; } catch { ioc = null; }
process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level: "info", step: "Lookup API", event: "lookup_forwarded", msg: "Forwarded single-IOC lookup to Enrich.", correlation_id: null, has_ioc: typeof ioc === "string" }) + "\n");
process.stdout.write(JSON.stringify({ lookup: { ioc } }));
