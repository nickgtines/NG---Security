// Human-readable Markdown for the Tines case description and case notes.
const arr = (v: unknown): any[] => (Array.isArray(v) ? v : []);
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const blank = (v: unknown) => v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0);

export const md = (v: unknown) => (blank(v) ? "—" : String(v).replace(/\|/g, "\\|").replace(/\r?\n/g, " "));
export const list = (v: unknown) => (arr(v).length ? arr(v).map(md).join(", ") : "—");

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
/** 2026-11-04T14:02:11.000Z -> "2026-11-04 14:02:11 UTC" */
export function when(v: unknown) {
  if (typeof v !== "string" || !ISO_RE.test(v)) return md(v);
  const d = new Date(v);
  return isNaN(d.getTime()) ? md(v) : d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

const ACRONYMS: Record<string, string> = { ip: "IP", ips: "IPs", upn: "UPN", id: "ID", mfa: "MFA", ioc: "IOC", iocs: "IOCs", os: "OS", asn: "ASN", isp: "ISP", url: "URL", sha256: "SHA256", tor: "Tor" };
export const humanize = (k: string) =>
  k.replace(/([a-z])([A-Z])/g, "$1_$2").split(/[_\s]+/).filter(Boolean)
    .map((w, i) => ACRONYMS[w.toLowerCase()] ?? (i === 0 ? w[0].toUpperCase() + w.slice(1).toLowerCase() : w.toLowerCase())).join(" ");

function scalar(v: unknown): string {
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (typeof v === "string" && ISO_RE.test(v)) return when(v);
  return md(v);
}
const isScalar = (v: unknown) => v === null || ["string", "number", "boolean"].includes(typeof v);
const isScalarList = (v: unknown) => Array.isArray(v) && v.every(isScalar);

/** Field/Value table from an object's scalar and scalar-list fields; nested objects are skipped. */
function kvTable(o: Record<string, any>, skip: string[] = []) {
  const rows = Object.entries(o)
    .filter(([k, v]) => !skip.includes(k) && !blank(v) && (isScalar(v) || isScalarList(v)))
    .map(([k, v]) => `| ${humanize(k)} | ${Array.isArray(v) ? v.map(scalar).join(", ") : scalar(v)} |`);
  return rows.length ? ["| Field | Value |", "|---|---|", ...rows].join("\n") : "";
}

const SEV_ICON: Record<string, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪", informational: "⚪" };
const VERDICT_ICON: Record<string, string> = { malicious: "🔴", suspicious: "🟠", clean: "🟢", unknown: "⚪" };
const RESULT_ICON: Record<string, string> = { match: "✅", no_match: "➖", error: "⚠️", skipped: "⏭️" };

// ---------- Description ----------
export function alertSection(rec: Record<string, any>) {
  const a = rec.alert;
  const host = [a.host?.hostname, a.host?.device_id, a.host?.os].filter((x) => !blank(x)).map(md).join(" · ");
  const user = a.user?.upn ? `${md(a.user.upn)}${a.user.display_name ? ` (${md(a.user.display_name)})` : ""}` : "—";
  return [
    "## Alert context",
    "| Field | Value |", "|---|---|",
    `| Alert | ${md(a.title)} |`,
    `| Severity | ${SEV_ICON[a.severity] ?? ""} ${md(a.severity)} |`,
    `| Source | ${a.source_url ? `[${md(a.source)}](${a.source_url})` : md(a.source)} |`,
    `| Rule | ${md(a.rule_name)} |`,
    `| Alert ID | ${md(a.id)} |`,
    `| First seen | ${when(a.first_seen)} |`, `| Last seen | ${when(a.last_seen)} |`,
    `| User | ${user} |`, `| Host | ${host || "—"} |`,
    `| Tactics | ${list(a.tactics)} |`, `| Techniques | ${list(a.techniques)} |`,
    `| Source IPs | ${list(a.network?.source_ips)} |`, `| Destination IPs | ${list(a.network?.destination_ips)} |`, `| Countries | ${list(a.network?.countries)} |`,
    `| Correlation ID | \`${md(rec.correlation_id)}\` |`,
    "", a.description ? `**Description:** ${md(a.description)}` : "",
  ].join("\n");
}

export function traceSection(trace: any[]) {
  const rows = trace.map((t) => `| ${md(t.component)} | ${md(t.decision)} | ${md(t.reason)} | ${md(t.duration_ms)} | ${t.error ? `⚠️ ${md(t.error)}` : "—"} |`);
  return ["## Automation trace", "| Component | Decision | Reason | ms | Error |", "|---|---|---|---|---|", ...rows].join("\n");
}

// ---------- Triage note ----------
export function triageNote(t: Record<string, any>) {
  const rows = arr(t.checks).map((c) => `| ${humanize(String(c.name ?? "—"))} | ${RESULT_ICON[c.result] ?? ""} ${md(humanize(String(c.result ?? "—")))} | ${md(c.detail)} |`);
  const out = [`**Disposition:** ${md(t.disposition)}`, "", `**Reason:** ${md(t.reason)}`, "",
    "| Check | Result | Detail |", "|---|---|---|", ...(rows.length ? rows : ["| — | — | No checks recorded |"])];
  if (t.matched_case_id) out.push("", `**Matched case:** ${md(t.matched_case_id)}`);
  if (isObj(t.matched_allowlist_entry)) out.push("", "**Matched allowlist entry**", "", kvTable(t.matched_allowlist_entry) || "_No fields._");
  return out.join("\n");
}

// ---------- Enrichment note ----------
/** Short, provider-specific highlights instead of the raw API response. */
function iocHighlights(r: Record<string, any>) {
  const raw = r.details?.raw ?? r.details ?? {};
  const p = String(r.provider ?? "").toLowerCase();
  const bits: string[] = [];
  if (p === "abuseipdb") {
    const d = raw.data ?? raw;
    if (d.abuseConfidenceScore != null) bits.push(`confidence ${d.abuseConfidenceScore}%`);
    if (d.totalReports != null) bits.push(`${d.totalReports} reports from ${d.numDistinctUsers ?? "?"} users`);
    if (d.isp) bits.push(`ISP ${d.isp}`);
    if (d.usageType) bits.push(d.usageType);
    if (d.countryCode) bits.push(`country ${d.countryCode}`);
    if (d.isTor) bits.push("Tor exit");
    if (d.lastReportedAt) bits.push(`last reported ${when(d.lastReportedAt)}`);
  } else if (p === "greynoise") {
    if (raw.classification) bits.push(`classification ${raw.classification}`);
    if (raw.name && raw.name !== "unknown") bits.push(raw.name);
    if (raw.noise != null) bits.push(raw.noise ? "internet scanner (noise)" : "not seen scanning");
    if (raw.riot) bits.push("known benign service (RIOT)");
    if (raw.last_seen) bits.push(`last seen ${raw.last_seen}`);
  } else if (p === "virustotal") {
    const at = raw.data?.attributes ?? {};
    const s = at.last_analysis_stats;
    if (s) bits.push(`${s.malicious ?? 0} malicious / ${s.suspicious ?? 0} suspicious of ${Object.values(s).reduce((x: number, y: any) => x + (Number(y) || 0), 0)} engines`);
    if (at.as_owner) bits.push(at.as_owner);
    if (at.asn) bits.push(`AS${at.asn}`);
    if (at.country) bits.push(`country ${at.country}`);
    if (at.reputation != null) bits.push(`reputation ${at.reputation}`);
  } else if (isObj(raw)) {
    for (const [k, v] of Object.entries(raw)) if (isScalar(v) && !blank(v) && bits.length < 5) bits.push(`${humanize(k)} ${scalar(v)}`);
  }
  return bits.length ? bits.map(md).join(" · ") : "—";
}

function iocLink(r: Record<string, any>) {
  const ioc = encodeURIComponent(String(r.ioc ?? ""));
  const p = String(r.provider ?? "").toLowerCase();
  if (!ioc) return "";
  if (p === "virustotal") return ` [↗](https://www.virustotal.com/gui/search/${ioc})`;
  if (p === "abuseipdb") return ` [↗](https://www.abuseipdb.com/check/${ioc})`;
  if (p === "greynoise") return ` [↗](https://viz.greynoise.io/ip/${ioc})`;
  return "";
}

function iocTable(results: any[]) {
  const rows = results.map((r) => `| ${md(r.ioc)} | ${md(r.ioc_type)} | ${md(r.provider)}${iocLink(r)} | ${VERDICT_ICON[r.verdict] ?? ""} ${md(r.verdict)} | ${md(r.score)} | ${r.error ? `⚠️ ${md(r.error)}` : iocHighlights(r)} |`);
  return ["| IOC | Type | Provider | Verdict | Score | Details |", "|---|---|---|---|---|---|", ...rows].join("\n");
}

const isSignin = (o: unknown): o is Record<string, any> => isObj(o) && ("time" in o || "timestamp" in o) && ("ip" in o || "country" in o);

/** Table of sign-ins / logins with columns chosen from whatever fields are present. */
function signinTable(rows: Record<string, any>[]) {
  const cols: [string, string, (r: any) => string][] = [
    ["Time", "time", (r) => when(r.time ?? r.timestamp)],
    ["IP", "ip", (r) => md(r.ip)], ["Country", "country", (r) => md(r.country)],
    ["City", "city", (r) => md(r.city)],
    ["Result", "success", (r) => (r.success === true ? "✅ Success" : r.success === false ? "❌ Failure" : md(r.result ?? r.outcome))],
    ["App", "app", (r) => md(r.app)], ["Client", "client_app", (r) => md(r.client_app ?? r.client)],
    ["Provider", "provider", (r) => md(r.provider)],
  ];
  const used = cols.filter(([, k]) => rows.some((r) => !blank(r[k]) || (k === "time" && !blank(r.timestamp)) || (k === "success" && (!blank(r.result) || !blank(r.outcome))) || (k === "client_app" && !blank(r.client))));
  return [`| ${used.map((c) => c[0]).join(" | ")} |`, `|${used.map(() => "---").join("|")}|`, ...rows.map((r) => `| ${used.map((c) => c[2](r)).join(" | ")} |`)].join("\n");
}

function contextTable(rows: [string, unknown][]) {
  return ["| Field | Value |", "|---|---|", ...rows.map(([k, v]) => `| ${k} | ${Array.isArray(v) ? list(v) : scalar(v)} |`)].join("\n");
}

export function enrichmentNote(e: Record<string, any> | null) {
  if (!e) return "_No enrichment was performed for this alert._";
  const s = e.ioc_summary ?? {};
  const u = e.user_context, h = e.host_context;
  const out = [
    "#### Indicators",
    `🔴 Malicious **${s.malicious ?? 0}** · 🟠 Suspicious **${s.suspicious ?? 0}** · 🟢 Clean **${s.clean ?? 0}** · ⚪ Unknown **${s.unknown ?? 0}**`, "",
    arr(e.ioc_results).length ? iocTable(arr(e.ioc_results)) : "_No indicators were looked up._", "",
    "#### User (Okta)",
  ];
  if (!u) out.push("_Not available._");
  else {
    if (u.error) out.push(`⚠️ ${md(u.error)}`, "");
    out.push(contextTable([["Status", u.status], ["Email", u.email], ["Groups", arr(u.groups)], ["MFA factors", arr(u.mfa_factors)], ["Last login", u.last_login]]
      .filter(([, v]) => !blank(v)) as [string, unknown][]));
    const logins = arr(u.recent_logins).filter(isObj).slice(0, 10).map((l) => ({ ...l, time: l.time ?? l.timestamp }));
    out.push("", `**Recent logins** (${logins.length ? `latest ${logins.length}` : "none"})`);
    if (logins.length) out.push("", signinTable(logins));
  }
  out.push("", "#### Host (CrowdStrike)");
  if (!h) out.push("_Not available — no host on this alert._");
  else {
    if (h.error) out.push(`⚠️ ${md(h.error)}`, "");
    out.push(contextTable(([["Found in Falcon", h.found], ["Hostname", h.hostname], ["Platform", h.platform], ["OS", h.os_version], ["Last seen", h.last_seen],
      ["Sensor version", h.sensor_version], ["Tags", arr(h.tags)], ["Containment", h.containment_status]] as [string, unknown][]).filter(([, v]) => !blank(v))));
  }
  return out.join("\n");
}

// ---------- Investigation note ----------
const isIocResult = (o: unknown): o is Record<string, any> => isObj(o) && "ioc" in o && "provider" in o;
const flat = (v: unknown): any[] => (Array.isArray(v) ? v.flatMap(flat) : [v]);

/** Turns a finding's evidence (often raw API objects) into tables and short field lists. */
function renderEvidence(evidence: unknown): string {
  const items = flat(evidence).filter((x) => !blank(x));
  if (!items.length) return "";
  const parts: string[] = [];
  const signins = items.filter(isSignin);
  const iocs = items.filter(isIocResult);
  const rest = items.filter((x) => !isSignin(x) && !isIocResult(x));
  if (iocs.length) parts.push(iocTable(iocs));
  if (signins.length) parts.push(signinTable(signins));
  for (const x of rest) {
    if (!isObj(x)) { parts.push(`- ${scalar(x)}`); continue; }
    const nestedSignins = Object.values(x).filter(Array.isArray).flatMap(flat).filter(isSignin);
    const fields = Object.entries(x).filter(([, v]) => !blank(v) && (isScalar(v) || isScalarList(v)))
      .map(([k, v]) => `- **${humanize(k)}:** ${Array.isArray(v) ? v.map(scalar).join(", ") : k === "reason" ? humanize(String(v)) : scalar(v)}`);
    if (fields.length) parts.push(fields.join("\n"));
    if (nestedSignins.length) parts.push(signinTable(nestedSignins));
    const nestedIocs = Object.values(x).filter(Array.isArray).flatMap(flat).filter(isIocResult);
    if (nestedIocs.length) parts.push(iocTable(nestedIocs));
  }
  return parts.join("\n\n");
}

const FINDING_RANK: Record<string, number> = { critical: -1, high: 0, medium: 1, low: 2, info: 3 };
const VERDICT_LABEL: Record<string, string> = { escalate: "🚨 Escalate", benign: "✅ Benign", needs_user_confirmation: "❓ Needs user confirmation" };

export function investigationNote(i: Record<string, any> | null) {
  if (!i) return "_No investigation was performed for this alert._";
  const findings = arr(i.findings).map((f, n) => ({ f, n }))
    .sort((a, b) => (FINDING_RANK[a.f.severity] ?? 9) - (FINDING_RANK[b.f.severity] ?? 9) || a.n - b.n).map(({ f }) => f);
  const out = [
    "| Verdict | Risk score | Findings |", "|---|---|---|",
    `| ${VERDICT_LABEL[i.verdict] ?? md(i.verdict)} | ${md(i.risk_score)}${typeof i.risk_score === "number" ? " / 100" : ""} | ${findings.length} |`,
  ];
  if (i.confirmation_question) out.push("", `> **Question sent to the user:** ${md(i.confirmation_question)}`);
  if (!findings.length) out.push("", "_No findings._");
  for (const f of findings) {
    out.push("", `#### ${SEV_ICON[f.severity] ?? "⚪"} ${humanize(String(f.check ?? "finding").replace(/^check_/, ""))} — ${md(f.severity)}`, "", md(f.finding));
    const ev = renderEvidence(f.evidence);
    if (ev) out.push("", "**Evidence**", "", ev);
  }
  if (i.code_version) out.push("", `_Investigation code: ${md(i.code_version)}_`);
  return out.join("\n");
}

export function investigationColor(i: Record<string, any> | null) {
  return i?.verdict === "escalate" ? "red" : i?.verdict === "benign" ? "green" : i?.verdict === "needs_user_confirmation" ? "gold" : "white";
}
