// Suspends the user in Okta for the user in the case metadata (metadata.email or metadata.username).
const ctx = JSON.parse(await Bun.stdin.text());
if (ctx.action !== "okta_suspend_user") process.exit(0); // Not this step's action: emit nothing.

const base = process.env.OKTA_ORG_URL!.replace(/\/$/, "");
const login = ctx.case.metadata?.email ?? ctx.case.metadata?.username;
const emit = (success: boolean, response: unknown) =>
  console.log(JSON.stringify({ context: ctx, result: { system: "Okta", target: login ?? null, success, response } }));

if (!login) {
  console.error(JSON.stringify({ event: "missing_target", case_id: ctx.case.id }));
  emit(false, { error: "Case metadata has no 'email' or 'username' to identify the Okta user." });
  process.exit(0);
}

const lookup = await fetch(`${base}/api/v1/users/${encodeURIComponent(login)}`, { headers: { accept: "application/json" } });
const user = await lookup.json().catch(() => ({}));
if (!lookup.ok) {
  console.error(JSON.stringify({ event: "okta_lookup_failed", status: lookup.status, case_id: ctx.case.id }));
  emit(false, { step: "lookup_user", status: lookup.status, body: user });
  process.exit(0);
}

const res = await fetch(`${base}/api/v1/users/${user.id}/lifecycle/suspend`, { method: "POST", headers: { accept: "application/json" } });
const text = await res.text();
let body: unknown = text;
try { body = text ? JSON.parse(text) : null; } catch {}
console.error(JSON.stringify({ event: "okta_action", action: ctx.action, status: res.status, okta_user_id: user.id, case_id: ctx.case.id }));
emit(res.ok, { okta_user_id: user.id, okta_login: user.profile?.login, prior_status: user.status, status: res.status, body });
