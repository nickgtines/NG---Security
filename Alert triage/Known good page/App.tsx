import { useEffect, useState } from "react";

declare global { interface Window { __ROUTE_PATH__: string } }
const API = `${window.__ROUTE_PATH__}/api`;
const TYPES = ["service_account", "scanner", "break_glass", "host"];

type Entry = { id: string; type: string; value: string; reason: string; owner: string; expires_at: string | null; added_by?: string };
const empty = { type: "service_account", value: "", reason: "", owner: "", expires_at: "" };

export default function App() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [form, setForm] = useState(empty);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { document.title = "Known-good list · Alert triage"; load(); }, []);

  async function call(init?: RequestInit, qs = "") {
    const r = await fetch(API + qs, init);
    const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
    if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
    return j;
  }
  async function load() {
    setLoading(true);
    try { setEntries((await call()).entries); setError(null); } catch (e) { setError((e as Error).message); }
    setLoading(false);
  }
  async function add(ev: React.FormEvent) {
    ev.preventDefault();
    try {
      await call({ method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...form, expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null }) });
      setForm(empty); await load();
    } catch (e) { setError((e as Error).message); }
  }
  async function remove(e: Entry) {
    if (!confirm(`Remove ${e.value} from the known-good list?`)) return;
    try { await call({ method: "DELETE" }, `?id=${encodeURIComponent(e.id)}`); await load(); } catch (err) { setError((err as Error).message); }
  }
  const expired = (e: Entry) => !!e.expires_at && new Date(e.expires_at) <= new Date();
  const input = "rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-purple-500 focus:outline-none";

  return (
    <div className="min-h-screen bg-slate-50 p-8 text-slate-900">
      <div className="mx-auto max-w-5xl space-y-6">
        <div>
          <h1 className="text-2xl font-semibold">Known-good list</h1>
          <p className="text-sm text-slate-600">Alerts whose user UPN or hostname matches an active entry are dismissed as DISMISS_KNOWN_GOOD. Expired entries are ignored.</p>
        </div>
        {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700">{error}</div>}
        <form onSubmit={add} className="grid grid-cols-1 gap-3 rounded-lg border border-slate-200 bg-white p-4 md:grid-cols-6">
          <select className={input} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
            {TYPES.map((t) => <option key={t}>{t}</option>)}
          </select>
          <input className={`${input} md:col-span-2`} placeholder="UPN or hostname" required value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
          <input className={input} placeholder="Owner" required value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
          <input className={input} type="datetime-local" title="Expires at (optional)" value={form.expires_at} onChange={(e) => setForm({ ...form, expires_at: e.target.value })} />
          <input className={`${input} md:col-span-5`} placeholder="Reason" required value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
          <button className="rounded-md bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700">Add entry</button>
        </form>
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-100 text-xs uppercase text-slate-500">
              <tr><th className="px-4 py-2">Value</th><th className="px-4 py-2">Type</th><th className="px-4 py-2">Reason</th><th className="px-4 py-2">Owner</th><th className="px-4 py-2">Expires</th><th /></tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={6} className="px-4 py-6 text-center text-slate-500">Loading…</td></tr>}
              {!loading && entries.length === 0 && <tr><td colSpan={6} className="px-4 py-6 text-center text-slate-500">No entries.</td></tr>}
              {entries.map((e) => (
                <tr key={e.id} className={`border-t border-slate-100 ${expired(e) ? "text-slate-400" : ""}`}>
                  <td className="px-4 py-2 font-mono">{e.value}</td>
                  <td className="px-4 py-2">{e.type}</td>
                  <td className="px-4 py-2">{e.reason}</td>
                  <td className="px-4 py-2">{e.owner}</td>
                  <td className="px-4 py-2">{e.expires_at ? `${new Date(e.expires_at).toLocaleString()}${expired(e) ? " (expired)" : ""}` : "Never"}</td>
                  <td className="px-4 py-2 text-right"><button onClick={() => remove(e)} className="text-red-600 hover:underline">Remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
