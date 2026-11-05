import { useState } from "react";

declare global {
  interface Window { __LOOKUP_API__: string }
}

type Result = {
  ioc: string; ioc_type: string; provider: string;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  score: number | null; details: Record<string, any>; cached: boolean; error: string | null;
};
type Lookup = { ioc: string; ioc_type: string; hash_type: string | null; ioc_results: Result[]; ioc_summary: Record<string, number>; duration_ms: number };

const VERDICT_STYLE: Record<string, string> = {
  malicious: "bg-red-100 text-red-800 ring-red-300",
  suspicious: "bg-amber-100 text-amber-800 ring-amber-300",
  clean: "bg-emerald-100 text-emerald-800 ring-emerald-300",
  unknown: "bg-slate-100 text-slate-700 ring-slate-300",
};
const PROVIDER_NAME: Record<string, string> = { greynoise: "GreyNoise", abuseipdb: "AbuseIPDB", virustotal: "VirusTotal", urlscan: "urlscan.io" };

function guessType(s: string) {
  const v = s.trim();
  if (!v) return "";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (v.includes(":") && /^[0-9a-f:.]+$/i.test(v))) return "ip";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
  if (/^https?:\/\//i.test(v)) return "url";
  if (/^[a-z0-9_.-]+\.[a-z]{2,}$/i.test(v)) return "domain";
  return "unrecognised";
}

export default function App() {
  const [ioc, setIoc] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<Lookup | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null); setData(null);
    try {
      const res = await fetch(window.__LOOKUP_API__, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ioc }) });
      const json = await res.json().catch(() => null);
      if (!res.ok) setError(json?.message ?? `Lookup failed (HTTP ${res.status}).`);
      else setData(json);
    } catch (err: any) {
      setError(err?.message ?? "Lookup failed.");
    } finally {
      setBusy(false);
    }
  }

  const hint = guessType(ioc);
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <title>IOC Lookup · Alert Enrichment</title>
      <div className="mx-auto max-w-6xl px-6 py-10">
        <h1 className="text-2xl font-semibold">IOC lookup</h1>
        <p className="mt-1 text-sm text-slate-600">One IOC through the same Alert Enrichment adapters the Orchestrator uses. Results are cached for 24 hours.</p>

        <form onSubmit={submit} className="mt-6 flex gap-3">
          <div className="relative flex-1">
            <input
              value={ioc} onChange={(e) => setIoc(e.target.value)} autoFocus
              placeholder="IP, domain, URL, or MD5/SHA1/SHA256 hash"
              className="w-full rounded-lg border border-slate-300 bg-white px-4 py-2.5 font-mono text-sm shadow-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-200"
            />
            {hint && <span className="absolute right-3 top-2.5 rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-600">{hint}</span>}
          </div>
          <button disabled={busy || !ioc.trim()} className="rounded-lg bg-sky-600 px-5 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-sky-700 disabled:opacity-50">
            {busy ? "Looking up…" : "Look up"}
          </button>
        </form>

        {error && <div className="mt-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{error}</div>}

        {data && (
          <div className="mt-8">
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <span className="font-mono font-medium break-all">{data.ioc}</span>
              <span className="rounded bg-slate-200 px-2 py-0.5 text-xs uppercase">{data.ioc_type}{data.hash_type ? ` · ${data.hash_type}` : ""}</span>
              <span className="text-slate-500">{data.duration_ms} ms</span>
              <span className="ml-auto flex gap-2">
                {Object.entries(data.ioc_summary).map(([k, v]) => (
                  <span key={k} className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${VERDICT_STYLE[k]}`}>{v} {k}</span>
                ))}
              </span>
            </div>
            <div className="mt-4 grid gap-4" style={{ gridTemplateColumns: `repeat(${data.ioc_results.length}, minmax(0, 1fr))` }}>
              {data.ioc_results.map((r) => (
                <div key={r.provider} className="flex min-w-0 flex-col rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="flex items-center justify-between">
                    <h2 className="font-medium">{PROVIDER_NAME[r.provider] ?? r.provider}</h2>
                    <span className="text-xs text-slate-500">{r.cached ? "cached" : "live"}</span>
                  </div>
                  <div className={`mt-3 self-start rounded-md px-3 py-1 text-sm font-semibold capitalize ring-1 ${VERDICT_STYLE[r.verdict]}`}>{r.verdict}</div>
                  <dl className="mt-3 space-y-1 text-sm">
                    <div className="flex justify-between"><dt className="text-slate-500">Score</dt><dd>{r.score ?? "—"}</dd></div>
                    {r.details?.note && <div className="text-slate-600">{r.details.note}</div>}
                    {r.error && <div className="text-red-700">Error: {r.error}</div>}
                  </dl>
                  <details className="mt-3 text-xs">
                    <summary className="cursor-pointer text-sky-700">Raw response</summary>
                    <pre className="mt-2 max-h-96 overflow-auto rounded bg-slate-900 p-3 text-slate-100">{JSON.stringify(r.details?.raw ?? r.details, null, 2)}</pre>
                  </details>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
