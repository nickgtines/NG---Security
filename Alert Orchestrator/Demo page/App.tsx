import { useEffect, useState } from 'react';
import { SAMPLES } from './samples';

declare global { interface Window { __API_BASE__: string } }
const API = window.__API_BASE__ ?? '';
type Rec = Record<string, any>;
type Result = { status: number; ms: number; body: Rec; label: string };

const SECTIONS = ['alert', 'triage', 'enrichment', 'investigation', 'response', 'case'] as const;
const badge: Record<string, string> = {
  SUPPRESS_DUPLICATE: 'bg-slate-200 text-slate-800', DISMISS_KNOWN_GOOD: 'bg-green-100 text-green-800',
  INVESTIGATE: 'bg-amber-100 text-amber-800', TRIAGE_ERROR: 'bg-red-100 text-red-800',
  escalate: 'bg-red-100 text-red-800', needs_user_confirmation: 'bg-amber-100 text-amber-800', benign: 'bg-green-100 text-green-800',
};
const slackLink = (ref: string) => {
  const [ch, ts] = ref.split(':');
  return ch && ts ? `https://slack.com/archives/${ch}/p${ts.replace('.', '')}` : null;
};

function Pill({ v }: { v?: string | null }) {
  if (!v) return null;
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${badge[v] ?? 'bg-sky-100 text-sky-800'}`}>{v}</span>;
}

function Timeline({ trace }: { trace: Rec[] }) {
  return (
    <ol className="relative border-l border-slate-300 ml-2">
      {trace.map((t, i) => (
        <li key={i} className="mb-4 ml-4">
          <div className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ${t.error ? 'bg-red-500' : 'bg-sky-500'}`} />
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-semibold">{t.component}</span><span className="text-slate-400">→</span>
            <Pill v={t.decision} /><span className="text-slate-500">{t.duration_ms} ms</span>
            {t.run_url ? <a className="text-sky-700 underline" href={t.run_url} target="_blank" rel="noreferrer">run</a> : <span className="text-xs text-slate-400">no run link</span>}
          </div>
          <p className="text-sm text-slate-700">{t.reason}</p>
          {t.error && <p className="text-sm text-red-700">Error: {t.error}</p>}
        </li>
      ))}
    </ol>
  );
}

function RecordView({ r }: { r: Result }) {
  const b = r.body;
  const rec = b.record ?? b;
  const trace: Rec[] = rec.trace ?? b.trace ?? [];
  const slack = (rec.response?.actions ?? []).filter((a: Rec) => a.type === 'slack_posted');
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`rounded px-2 py-1 text-sm font-mono ${r.status === 200 ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>HTTP {r.status}</span>
        <span className="font-medium">{r.label}</span><span className="text-sm text-slate-500">{r.ms} ms</span>
        <Pill v={rec.triage?.disposition} /><Pill v={rec.investigation?.verdict} />
        {rec.correlation_id && <code className="text-xs text-slate-500">{rec.correlation_id}</code>}
      </div>
      {b.error && <p className="rounded bg-red-50 p-3 text-sm text-red-800">{b.error}</p>}
      {rec.investigation?.confirmation_question && <p className="rounded bg-amber-50 p-3 text-sm">Question for user: {rec.investigation.confirmation_question}</p>}
      <div className="flex flex-wrap gap-3 text-sm">
        {rec.case?.url && <a className="rounded bg-purple-600 px-3 py-1.5 text-white" href={rec.case.url} target="_blank" rel="noreferrer">Tines case {rec.case.id}</a>}
        {!rec.case?.url && rec.case?.id && <span className="rounded bg-purple-100 px-3 py-1.5">Case {rec.case.id}</span>}
        {slack.map((a: Rec) => slackLink(a.ref) && <a key={a.ref} className="rounded bg-slate-800 px-3 py-1.5 text-white" href={slackLink(a.ref)!} target="_blank" rel="noreferrer">Slack message</a>)}
      </div>
      <section><h2 className="mb-2 font-semibold">Trace</h2><Timeline trace={trace} /></section>
      {rec.alert && (
        <section className="space-y-2"><h2 className="font-semibold">Component output</h2>
          {SECTIONS.map((s) => (
            <details key={s} className="rounded border border-slate-200 bg-white">
              <summary className="cursor-pointer px-3 py-2 text-sm font-medium">{s}{rec[s] == null && <span className="ml-2 text-slate-400">null</span>}</summary>
              <pre className="max-h-96 overflow-auto bg-slate-50 p-3 text-xs">{JSON.stringify(s === 'alert' ? { ...rec.alert, raw: '…' } : rec[s], null, 2)}</pre>
            </details>
          ))}
        </section>
      )}
    </div>
  );
}

export default function App() {
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [runs, setRuns] = useState<Rec[]>([]);
  const loadRuns = () => fetch(`${API}/runs`).then((r) => r.json()).then((d) => setRuns(d.runs ?? [])).catch(() => {});
  useEffect(() => { loadRuns(); }, []);

  async function send(s: (typeof SAMPLES)[number]) {
    setBusy(s.key); setResult(null);
    const t = performance.now();
    try {
      const r = await fetch(`${API}${s.route}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(s.body) });
      const text = await r.text();
      let body: Rec; try { body = JSON.parse(text); } catch { body = { error: text || `HTTP ${r.status}` }; }
      setResult({ status: r.status, ms: Math.round(performance.now() - t), body, label: s.label });
    } catch (e) {
      setResult({ status: 0, ms: 0, body: { error: String(e) }, label: s.label });
    }
    setBusy(null); loadRuns();
  }
  async function openRun(id: string) {
    const r = await fetch(`${API}/runs?id=${encodeURIComponent(id)}`);
    const d = await r.json();
    setResult({ status: d.http_status ?? r.status, ms: 0, body: d.record ? d.record : d, label: `Stored run ${id.slice(0, 8)}` });
  }

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <header className="bg-slate-900 px-6 py-4 text-white"><h1 className="text-xl font-semibold">Alert Orchestrator</h1>
        <p className="text-sm text-slate-300">Ingest → Triage → (Enrichment → Investigation) → Response. Contract v3, deterministic.</p></header>
      <main className="mx-auto grid max-w-7xl gap-6 p-6 lg:grid-cols-[320px_1fr]">
        <aside className="space-y-6">
          <section className="space-y-2"><h2 className="font-semibold">Send a sample</h2>
            {SAMPLES.map((s) => (
              <button key={s.key} disabled={!!busy} onClick={() => send(s)}
                className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-left hover:bg-sky-50 disabled:opacity-50">
                <div className="text-sm font-medium">{busy === s.key ? 'Running…' : s.label}</div>
                <div className="text-xs text-slate-500">{s.route} · expect {s.expect}</div>
              </button>
            ))}
          </section>
          <section><div className="mb-2 flex items-center justify-between"><h2 className="font-semibold">Recent runs</h2>
            <button className="text-xs text-sky-700" onClick={loadRuns}>Refresh</button></div>
            <ul className="space-y-1">
              {runs.length === 0 && <li className="text-sm text-slate-500">No runs yet.</li>}
              {runs.map((r) => (
                <li key={r.correlation_id}><button onClick={() => openRun(r.correlation_id)} className="w-full rounded bg-white px-2 py-1.5 text-left text-xs hover:bg-sky-50">
                  <div className="truncate font-medium">{r.title}</div>
                  <div className="flex flex-wrap gap-1 text-slate-500">{r.source} · {new Date(r.stored_at).toLocaleTimeString()} · {r.http_status !== 200 ? `HTTP ${r.http_status}` : <><Pill v={r.disposition} /><Pill v={r.verdict} /></>}</div>
                </button></li>
              ))}
            </ul>
          </section>
        </aside>
        <section className="rounded-lg bg-white p-5 shadow-sm">
          {result ? <RecordView r={result} /> : <p className="text-slate-500">{busy ? 'Running the pipeline (up to ~2 minutes)…' : 'Pick a sample to run it through the orchestrator.'}</p>}
        </section>
      </main>
    </div>
  );
}
