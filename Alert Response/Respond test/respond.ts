// Alert Response core logic (shared contract v3). Deterministic, no AI.
import config from "./config.json";

export const COMPONENT = "alert-response";
const HTTP_TIMEOUT_MS = 15_000;

let correlationId = "unknown";
export function log(event: string, data: Record<string, unknown> = {}) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), component: COMPONENT, correlation_id: correlationId, run_id: process.env._3B_RUN_ID ?? null, event, ...data }));
}

export class ContractError extends Error {}

const SOURCES = ["sentinel", "crowdstrike"];
const SEVERITIES = ["informational", "low", "medium", "high", "critical"];
const DISPOSITIONS = ["SUPPRESS_DUPLICATE", "DISMISS_KNOWN_GOOD", "INVESTIGATE", "TRIAGE_ERROR"];
const VERDICTS = ["escalate", "benign", "needs_user_confirmation"];
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStrOrNull = (v: unknown) => v === null || typeof v === "string";
const arr = (v: unknown): any[] => (Array.isArray(v) ? v : []);

export function validate(rec: unknown): asserts rec is Record<string, any> {
  const errs: string[] = [];
  if (!isObj(rec)) throw new ContractError("Body must be a JSON object (alert record, schema_version 3).");
  if (rec.schema_version !== "3") errs.push('schema_version must be "3"');
  if (typeof rec.correlation_id !== "string" || !rec.correlation_id) errs.push("correlation_id must be a non-empty string");
  if (typeof rec.dedup_key !== "string" || !/^[0-9a-f]{64}$/i.test(rec.dedup_key)) errs.push("dedup_key must be a 64-character hex sha256");
  if (!Array.isArray(rec.trace)) errs.push("trace must be an array");
  const a = rec.alert;
  if (!isObj(a)) errs.push("alert must be an object");
  else {
    for (const k of ["id", "rule_name", "title"]) if (typeof a[k] !== "string" || !a[k]) errs.push(`alert.${k} must be a non-empty string`);
    if (!SOURCES.includes(a.source)) errs.push(`alert.source must be one of ${SOURCES.join(", ")}`);
    if (!SEVERITIES.includes(a.severity)) errs.push(`alert.severity must be one of ${SEVERITIES.join(", ")}`);
    if (!isStrOrNull(a.source_url ?? null)) errs.push("alert.source_url must be string|null");
    if (!isObj(a.user) || !isStrOrNull(a.user.upn)) errs.push("alert.user must be an object with upn string|null");
    if (!isObj(a.host) || !isStrOrNull(a.host.hostname)) errs.push("alert.host must be an object with hostname string|null");
  }
  const t = rec.triage;
  if (!isObj(t)) errs.push("triage must be an object (Alert Response needs a completed triage section)");
  else {
    if (!DISPOSITIONS.includes(t.disposition)) errs.push(`triage.disposition must be one of ${DISPOSITIONS.join(", ")}`);
    if (t.disposition === "SUPPRESS_DUPLICATE" && (t.matched_case_id === null || t.matched_case_id === undefined || String(t.matched_case_id) === ""))
      errs.push("triage.matched_case_id is required when disposition is SUPPRESS_DUPLICATE");
    if (t.checks !== undefined && !Array.isArray(t.checks)) errs.push("triage.checks must be an array");
  }
  if (rec.enrichment != null && !isObj(rec.enrichment)) errs.push("enrichment must be null or an object");
  const inv = rec.investigation;
  if (inv != null) {
    if (!isObj(inv)) errs.push("investigation must be null or an object");
    else {
      if (!VERDICTS.includes(inv.verdict)) errs.push(`investigation.verdict must be one of ${VERDICTS.join(", ")}`);
      if (inv.verdict === "needs_user_confirmation" && (typeof inv.confirmation_question !== "string" || !inv.confirmation_question))
        errs.push("investigation.confirmation_question is required when verdict is needs_user_confirmation");
      if (inv.findings !== undefined && !Array.isArray(inv.findings)) errs.push("investigation.findings must be an array");
    }
  }
  if (errs.length) throw new ContractError(`Invalid alert record: ${errs.join("; ")}.`);
}

// ---------- HTTP helpers ----------
const tinesBase = () => "https://" + process.env.TINES_URL!.replace(/^(https?:\/\/)+/, "").replace(/\/+$/, "");

async function call(service: string, url: string, init: RequestInit = {}) {
  const r = await fetch(url, { ...init, headers: { "content-type": "application/json", accept: "application/json", ...(init.headers ?? {}) }, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  const text = await r.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  log("http_call", { service, method: init.method ?? "GET", url: url.replace(/\?.*$/, ""), status: r.status });
  return { status: r.status, ok: r.ok, body, text };
}

async function tines(path: string, method = "GET", payload?: unknown) {
  const r = await call("tines", `${tinesBase()}${path}`, { method, body: payload === undefined ? undefined : JSON.stringify(payload) });
  if (!r.ok) throw new Error(`Tines ${method} ${path} returned HTTP ${r.status}: ${r.text.slice(0, 300)}`);
  return r.body;
}

async function slackPost(payload: Record<string, unknown>) {
  const r = await call("slack", "https://slack.com/api/chat.postMessage", { method: "POST", headers: { "content-type": "application/json; charset=utf-8" }, body: JSON.stringify(payload) });
  if (!r.ok || !r.body?.ok) throw new Error(`Slack chat.postMessage failed: HTTP ${r.status} ${r.body?.error ?? r.text.slice(0, 200)}`);
  return { channel: String(r.body.channel), ts: String(r.body.ts) };
}

// ---------- Formatting ----------
const md = (v: unknown) => (v === null || v === undefined || v === "" ? "—" : String(v).replace(/\|/g, "\\|").replace(/\r?\n/g, " "));
const list = (v: unknown) => (arr(v).length ? arr(v).map(md).join(", ") : "—");
const slackEsc = (v: unknown) => String(v ?? "—").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const PRIORITY: Record<string, string> = { informational: "info", low: "low", medium: "medium", high: "high", critical: "critical" };
const SEV_EMOJI: Record<string, string> = { informational: ":white_circle:", low: ":large_blue_circle:", medium: ":large_yellow_circle:", high: ":large_orange_circle:", critical: ":red_circle:" };
const FINDING_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };

function alertSection(rec: Record<string, any>) {
  const a = rec.alert;
  return [
    "## Alert",
    `| Field | Value |\n|---|---|`,
    `| Alert ID | ${md(a.id)} |`, `| Source | ${md(a.source)} |`, `| Rule | ${md(a.rule_name)} |`, `| Severity | ${md(a.severity)} |`,
    `| First seen | ${md(a.first_seen)} |`, `| Last seen | ${md(a.last_seen)} |`,
    `| User | ${md(a.user?.upn)} (${md(a.user?.display_name)}) |`,
    `| Host | ${md(a.host?.hostname)} / ${md(a.host?.device_id)} / ${md(a.host?.os)} |`,
    `| Tactics | ${list(a.tactics)} |`, `| Techniques | ${list(a.techniques)} |`,
    `| Source IPs | ${list(a.network?.source_ips)} |`, `| Destination IPs | ${list(a.network?.destination_ips)} |`, `| Countries | ${list(a.network?.countries)} |`,
    `| Correlation ID | ${md(rec.correlation_id)} |`, `| Dedup key | ${md(rec.dedup_key)} |`,
    "",
    a.source_url ? `[Open alert in ${a.source}](${a.source_url})` : "_No source URL provided._",
    "",
    "**Description**", "", md(a.description),
  ].join("\n");
}

function triageSection(t: Record<string, any>) {
  const rows = arr(t.checks).map((c) => `| ${md(c.name)} | ${md(c.result)} | ${md(c.detail)} |`);
  return ["## Triage", `**Disposition:** ${md(t.disposition)}`, "", `**Reason:** ${md(t.reason)}`, "",
    "| Check | Result | Detail |\n|---|---|---|", ...(rows.length ? rows : ["| — | — | No checks recorded |"])].join("\n");
}

function enrichmentSection(e: Record<string, any> | null) {
  if (!e) return "## Enrichment\n_No enrichment section was provided._";
  const iocRows = arr(e.ioc_results).map((r) => `| ${md(r.ioc)} (${md(r.ioc_type)}) | ${md(r.provider)} | ${md(r.verdict)} | ${md(r.score)} |${r.error ? ` error: ${md(r.error)}` : ""}`);
  const s = e.ioc_summary ?? {};
  const u = e.user_context, h = e.host_context;
  const logins = arr(u?.recent_logins).slice(0, 10).map((l) => `${md(l.time)} ${md(l.ip)} ${md(l.country)}`).join("; ");
  return [
    "## Enrichment",
    `**IOC summary:** malicious ${s.malicious ?? 0}, suspicious ${s.suspicious ?? 0}, clean ${s.clean ?? 0}, unknown ${s.unknown ?? 0}`, "",
    "| IOC | Provider | Verdict | Score |\n|---|---|---|---|", ...(iocRows.length ? iocRows : ["| — | — | — | — |"]), "",
    "**User context (Okta)**", "",
    u ? [`| Field | Value |\n|---|---|`, `| Status | ${md(u.status)} |`, `| Groups | ${list(u.groups)} |`, `| MFA factors | ${list(u.mfa_factors)} |`,
         `| Last login | ${md(u.last_login)} |`, `| Recent logins | ${logins || "—"} |`, `| Error | ${md(u.error)} |`].join("\n") : "_Not available._", "",
    "**Host context (CrowdStrike)**", "",
    h ? [`| Field | Value |\n|---|---|`, `| Found | ${md(h.found)} |`, `| Platform | ${md(h.platform)} |`, `| Last seen | ${md(h.last_seen)} |`,
         `| Sensor version | ${md(h.sensor_version)} |`, `| Tags | ${list(h.tags)} |`, `| Containment | ${md(h.containment_status)} |`, `| Error | ${md(h.error)} |`].join("\n") : "_Not available._",
  ].join("\n");
}

function investigationSection(i: Record<string, any> | null) {
  if (!i) return "## Investigation\n_No investigation section was provided._";
  const f = arr(i.findings).map((x) => `- **[${md(x.severity)}] ${md(x.check)}:** ${md(x.finding)}${arr(x.evidence).length ? `\n  - Evidence: \`${JSON.stringify(x.evidence).slice(0, 1500).replace(/`/g, "'")}\`` : ""}`);
  return ["## Investigation", `**Verdict:** ${md(i.verdict)}  `, `**Risk score:** ${md(i.risk_score)}  `, `**Code version:** ${md(i.code_version)}`,
    i.confirmation_question ? `\n**Confirmation question:** ${md(i.confirmation_question)}` : "", "", "**Findings**", "", ...(f.length ? f : ["_None._"])].join("\n");
}

function traceSection(trace: any[]) {
  const rows = trace.map((t) => `| ${md(t.component)} | ${md(t.decision)} | ${md(t.duration_ms)} | ${md(t.error)} |`);
  return ["## Automation trace", "| Component | Decision | ms | Error |\n|---|---|---|---|", ...rows].join("\n");
}

const traceHasError = (trace: any[]) => trace.some((t) => t && t.error);
const caseName = (rec: Record<string, any>) => `[${rec.alert.severity.toUpperCase()}] ${rec.alert.title}`.slice(0, 250);

function caseRef(c: any) {
  return { id: String(c.case_id ?? c.id), url: c.url ?? null, status: c.status ? String(c.status).toLowerCase() : null };
}

// ---------- Case actions ----------
// Metadata keys read by the "Tines case action handler" workflow: email/username (Okta),
// hostname/host/device_id (CrowdStrike host), process_name/process_id/sha256 (CrowdStrike process).
const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : typeof v === "number" ? String(v) : null);

function actionTargets(rec: Record<string, any>) {
  const a = rec.alert;
  const email = str(a.user?.upn) ?? str(rec.enrichment?.user_context?.email);
  const hostname = str(a.host?.hostname);
  const deviceId = str(a.host?.device_id);
  const proc = isObj(a.process) ? a.process : {};
  const evProc = arr(a.evidence).find((e) => e?.type === "process")?.details ?? {};
  const processName = str(proc.name) ?? str(proc.process_name) ?? str(evProc.process_name) ?? str(evProc.name);
  const processId = str(proc.id) ?? str(proc.pid) ?? str(proc.process_id) ?? str(evProc.process_id) ?? str(evProc.pid);
  const sha256 = str(proc.sha256) ?? str(evProc.sha256) ?? arr(a.iocs?.hashes).map(str).find((h) => h && /^[0-9a-f]{64}$/i.test(h)) ?? null;
  return { email, hostname, deviceId, processName, processId, sha256 };
}

function caseActionMetadata(t: ReturnType<typeof actionTargets>) {
  const m: Record<string, string> = {};
  if (t.email) { m.email = t.email; m.username = t.email; }
  if (t.hostname) { m.hostname = t.hostname; m.host = t.hostname; }
  if (t.deviceId) m.device_id = t.deviceId;
  if (t.processName) m.process_name = t.processName;
  if (t.processId) m.process_id = t.processId;
  if (t.sha256) m.sha256 = t.sha256;
  return m;
}

// Picks buttons by alert source: Sentinel (sign-in) → Okta actions, CrowdStrike → CrowdStrike actions.
// Every case gets Create Slack Channel. A source action is only offered when its target metadata exists.
function selectCaseActions(rec: Record<string, any>, t: ReturnType<typeof actionTargets>) {
  const labels: string[] = [];
  if (rec.alert.source === "sentinel" && t.email) labels.push("Get User Details", "Revoke Sessions", "Force Password Reset", "Suspend User");
  if (rec.alert.source === "crowdstrike" && (t.hostname || t.deviceId)) {
    labels.push("Contain Host");
    if (t.processName || t.processId || t.sha256) labels.push("Kill Process");
  }
  labels.push("Create Slack Channel");
  return labels;
}

async function addCaseActions(ctx: Ctx, labels: string[]) {
  for (const label of labels) {
    try {
      const r = await tines(`/api/v2/cases/${encodeURIComponent(ctx.caseOut.id!)}/actions`, "POST", { url: config.case_actions_webhook_url, label, action_type: "webhook", action_text: label });
      ctx.actions.push({ type: "case_action_added", ref: `${ctx.caseOut.id}#${label}#${r?.id ?? "unknown"}` });
    } catch (e) { fail(ctx, `add case action "${label}"`, e); }
  }
}

// ---------- Behaviours ----------
type Ctx = { rec: Record<string, any>; actions: { type: string; ref: string }[]; errors: string[]; caseOut: { id: string | null; url: string | null; status: string | null } };

function fail(ctx: Ctx, what: string, e: unknown) {
  const msg = `${what}: ${(e as Error).message}`;
  ctx.errors.push(msg);
  log("action_error", { action: what, error: msg });
}

async function suppressDuplicate(ctx: Ctx) {
  const id = String(ctx.rec.triage.matched_case_id);
  ctx.caseOut = { id, url: null, status: null };
  try {
    const text = `Duplicate alert ${ctx.rec.alert.id} suppressed at ${new Date().toISOString()} (correlation ${ctx.rec.correlation_id})`;
    const c = await tines(`/api/v2/cases/${encodeURIComponent(id)}/comments`, "POST", { value: text });
    ctx.actions.push({ type: "case_commented", ref: `${id}#comment-${c?.id ?? "unknown"}` });
  } catch (e) { fail(ctx, `comment on case ${id}`, e); }
  try {
    const c = await tines(`/api/v2/cases/${encodeURIComponent(id)}`);
    ctx.caseOut = caseRef(c);
  } catch (e) { fail(ctx, `fetch case ${id}`, e); }
}

async function dismissKnownGood(ctx: Ctx) {
  const rec = ctx.rec;
  const entry = rec.triage.matched_allowlist_entry ?? null;
  const description = [
    `Automatically closed: alert matched a known-good entry during triage.`, "",
    "## Matched allowlist entry", "```json", JSON.stringify(entry, null, 2), "```", "",
    triageSection(rec.triage), "", alertSection(rec), "", traceSection(rec.trace),
  ].join("\n");
  try {
    const now = new Date().toISOString();
    const c = await tines("/api/v2/cases", "POST", {
      team_id: config.tines_team_id, name: `Known-good: ${caseName(rec)}`.slice(0, 250), description,
      priority: PRIORITY[rec.alert.severity], status: "closed", resolved_at: now,
      tag_names: ["known-good", `dedup:${rec.dedup_key}`, `source:${rec.alert.source}`, `severity:${rec.alert.severity}`],
      metadata: { correlation_id: rec.correlation_id, alert_id: rec.alert.id, allowlist_entry: JSON.stringify(entry).slice(0, 2000) },
    });
    ctx.caseOut = caseRef(c);
    ctx.caseOut.status = ctx.caseOut.status ?? "closed";
    ctx.actions.push({ type: "case_created", ref: ctx.caseOut.id! });
  } catch (e) { fail(ctx, "create known-good case", e); }
  try {
    const who = rec.alert.user?.upn ?? rec.alert.host?.hostname ?? "unknown";
    const caseTxt = ctx.caseOut.url ? `<${ctx.caseOut.url}|case ${ctx.caseOut.id}>` : "no case (creation failed)";
    const msg = await slackPost({ channel: config.slack_log_channel, unfurl_links: false,
      text: `:white_check_mark: Known-good dismissed: ${slackEsc(rec.alert.title)} (${slackEsc(who)}, ${rec.alert.severity}) — ${caseTxt} — correlation ${rec.correlation_id}` });
    ctx.actions.push({ type: "slack_posted", ref: `${msg.channel}:${msg.ts}` });
  } catch (e) { fail(ctx, `post to ${config.slack_log_channel}`, e); }
}

async function investigate(ctx: Ctx) {
  const rec = ctx.rec;
  const inv = rec.investigation ?? null;
  const verdict = inv?.verdict ?? "none";
  const hasErr = traceHasError(rec.trace);
  const tags = [`dedup:${rec.dedup_key}`, `source:${rec.alert.source}`, `severity:${rec.alert.severity}`, `verdict:${verdict}`];
  if (hasErr) tags.push("automation-error");
  const description = [
    `Correlation ID: \`${rec.correlation_id}\``, rec.alert.source_url ? `Source alert: [${rec.alert.source_url}](${rec.alert.source_url})` : "", "",
    triageSection(rec.triage), "", enrichmentSection(rec.enrichment ?? null), "", investigationSection(inv), "", alertSection(rec), "", traceSection(rec.trace),
  ].join("\n");

  const targets = actionTargets(rec);
  try {
    const c = await tines("/api/v2/cases", "POST", {
      team_id: config.tines_team_id, name: caseName(rec), description, priority: PRIORITY[rec.alert.severity], status: "open", tag_names: tags,
      metadata: { correlation_id: rec.correlation_id, alert_id: rec.alert.id, dedup_key: rec.dedup_key, source: rec.alert.source, source_url: rec.alert.source_url ?? "", ...caseActionMetadata(targets) },
    });
    ctx.caseOut = caseRef(c);
    ctx.actions.push({ type: "case_created", ref: ctx.caseOut.id! });
  } catch (e) { fail(ctx, "create case", e); }

  if (ctx.caseOut.id) {
    const labels = selectCaseActions(rec, targets);
    log("case_actions_selected", { case_id: ctx.caseOut.id, labels });
    await addCaseActions(ctx, labels);
  }

  // Triage (Alert triage v3) searches cases by dedup tag directly; register in its dedup index only if configured.
  if (ctx.caseOut.id && config.triage_dedup_index_url) {
    try {
      const r = await call("alert-triage", config.triage_dedup_index_url, { method: "POST", body: JSON.stringify({ dedup_key: rec.dedup_key, case_id: ctx.caseOut.id, correlation_id: rec.correlation_id }) });
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${r.text.slice(0, 200)}`);
      ctx.actions.push({ type: "case_updated", ref: `${ctx.caseOut.id}#dedup-index` });
    } catch (e) { fail(ctx, "register case in triage dedup index", e); }
  }

  let slackMsg: { channel: string; ts: string } | null = null;
  try {
    const a = rec.alert;
    const s = rec.enrichment?.ioc_summary ?? {};
    const top = arr(inv?.findings).map((f, i) => ({ f, i })).sort((x, y) => (FINDING_RANK[x.f.severity] ?? 9) - (FINDING_RANK[y.f.severity] ?? 9) || x.i - y.i).slice(0, 3).map(({ f }) => f);
    const blocks: any[] = [
      { type: "header", text: { type: "plain_text", text: `${a.severity.toUpperCase()}: ${a.title}`.slice(0, 150) } },
      { type: "section", fields: [
        { type: "mrkdwn", text: `*Severity*\n${SEV_EMOJI[a.severity]} ${a.severity}` },
        { type: "mrkdwn", text: `*Verdict*\n${slackEsc(verdict)}` },
        { type: "mrkdwn", text: `*User*\n${slackEsc(a.user?.upn ?? "—")}` },
        { type: "mrkdwn", text: `*Host*\n${slackEsc(a.host?.hostname ?? "—")}` },
        { type: "mrkdwn", text: `*Risk score*\n${inv?.risk_score ?? "—"}` },
        { type: "mrkdwn", text: `*IOCs*\n:red_circle: ${s.malicious ?? 0} malicious · :large_orange_circle: ${s.suspicious ?? 0} suspicious · :white_circle: ${s.clean ?? 0} clean · ${s.unknown ?? 0} unknown` },
      ] },
      { type: "section", text: { type: "mrkdwn", text: `*Top findings*\n${top.length ? top.map((f) => `• [${slackEsc(f.severity)}] ${slackEsc(f.finding)}`).join("\n") : "_None_"}`.slice(0, 2900) } },
    ];
    if (hasErr) {
      const errs = rec.trace.filter((t: any) => t?.error).map((t: any) => `${t.component}: ${t.error}`).join("; ");
      blocks.push({ type: "section", text: { type: "mrkdwn", text: `:warning: *Automation error* — results may be incomplete. ${slackEsc(errs)}`.slice(0, 2900) } });
    }
    if (ctx.caseOut.url) blocks.push({ type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "View case" }, url: ctx.caseOut.url, style: "primary", action_id: "view_case" }] });
    else blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: ":warning: Case creation failed — see the alert record." }] });
    blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: `${a.source} · ${slackEsc(a.rule_name)} · correlation ${rec.correlation_id}` }] });
    slackMsg = await slackPost({ channel: config.slack_alerts_channel, text: `${a.severity.toUpperCase()}: ${a.title} (${verdict})`, blocks, unfurl_links: false });
    ctx.actions.push({ type: "slack_posted", ref: `${slackMsg.channel}:${slackMsg.ts}` });
  } catch (e) { fail(ctx, `post to ${config.slack_alerts_channel}`, e); }

  if (inv?.verdict === "needs_user_confirmation") {
    try {
      if (!ctx.caseOut.id || !ctx.caseOut.url) throw new Error("no case was created");
      if (!slackMsg) throw new Error(`no ${config.slack_alerts_channel} message to thread on`);
      if (!rec.alert.user?.upn) throw new Error("alert.user.upn is null");
      const base = process.env.WORKFLOW_URL!.replace(/\/+$/, "");
      const r = await call("security-reachout", `${base}/reachout`, { method: "POST", body: JSON.stringify({
        correlation_id: rec.correlation_id, case_id: ctx.caseOut.id, case_url: ctx.caseOut.url, user_upn: rec.alert.user.upn,
        question: inv.confirmation_question, alert_title: rec.alert.title, slack_channel: slackMsg.channel, slack_thread_ts: slackMsg.ts,
      }) });
      if (r.status !== 202) throw new Error(`expected 202, got HTTP ${r.status}: ${r.text.slice(0, 200)}`);
      ctx.actions.push({ type: "reachout_sent", ref: String(r.body?.reachout_id ?? "accepted") });
    } catch (e) { fail(ctx, "security reachout", e); }
  }
}

export async function respond(rec: Record<string, any>) {
  const started = Date.now();
  correlationId = rec.correlation_id;
  const disposition = rec.triage.disposition;
  log("response_start", { alert_id: rec.alert.id, disposition, verdict: rec.investigation?.verdict ?? null });
  const ctx: Ctx = { rec, actions: [], errors: [], caseOut: { id: rec.case?.id ?? null, url: rec.case?.url ?? null, status: rec.case?.status ?? null } };
  try {
    if (disposition === "SUPPRESS_DUPLICATE") await suppressDuplicate(ctx);
    else if (disposition === "DISMISS_KNOWN_GOOD") await dismissKnownGood(ctx);
    else await investigate(ctx);
  } catch (e) { fail(ctx, "unexpected", e); }

  const summary = ctx.actions.map((a) => a.type).join(", ") || "no actions";
  const decision = disposition === "SUPPRESS_DUPLICATE" ? "commented_duplicate" : disposition === "DISMISS_KNOWN_GOOD" ? "closed_known_good" : "case_opened";
  const traceEntry = {
    component: COMPONENT, decision: ctx.errors.length ? `${decision}_with_errors` : decision,
    reason: `${disposition}${rec.investigation?.verdict ? ` / ${rec.investigation.verdict}` : ""}: ${summary}.`,
    duration_ms: Date.now() - started, run_url: process.env._3B_RUN_URL || null,
    error: ctx.errors.length ? ctx.errors.join("; ") : null,
  };
  log("response_done", { decision: traceEntry.decision, actions: ctx.actions, errors: ctx.errors, case_id: ctx.caseOut.id, duration_ms: traceEntry.duration_ms });
  return { ...rec, case: ctx.caseOut, response: { actions: ctx.actions, errors: ctx.errors }, trace: [...rec.trace, traceEntry] };
}

export function httpResponse(status: number, body: unknown) {
  const text = JSON.stringify(body);
  const reasons: Record<number, string> = { 200: "OK", 400: "Bad Request", 405: "Method Not Allowed" };
  return `HTTP/1.1 ${status} ${reasons[status] ?? "OK"}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(text)}\r\n\r\n${text}`;
}

export function parseRequest(raw: string) {
  const i = raw.indexOf("\r\n\r\n");
  const head = i >= 0 ? raw.slice(0, i) : raw;
  const [method = "", target = "/"] = (head.split("\r\n")[0] ?? "").split(" ");
  return { method: method.toUpperCase(), path: target, body: i >= 0 ? raw.slice(i + 4) : "" };
}

export async function handle(raw: string, sample?: unknown) {
  try {
    const req = parseRequest(raw);
    let rec: unknown;
    if (sample !== undefined && (req.method === "GET" || !req.body.trim())) rec = sample;
    else {
      if (req.method !== "POST") return httpResponse(405, { error: "Use POST with an alert record (schema_version 3) as the JSON body." });
      try { rec = JSON.parse(req.body); } catch { return httpResponse(400, { error: "Body is not valid JSON." }); }
    }
    try { validate(rec); } catch (e) {
      if (e instanceof ContractError) { log("invalid_input", { error: e.message }); return httpResponse(400, { error: e.message }); }
      throw e;
    }
    return httpResponse(200, await respond(rec));
  } catch (e) {
    log("handler_error", { error: (e as Error).message });
    return httpResponse(400, { error: `Could not process request: ${(e as Error).message}` });
  }
}
