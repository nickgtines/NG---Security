// Looks up the case user in Okta (read-only) and returns key profile details.
const ctx = JSON.parse(await Bun.stdin.text());
if (ctx.action !== "okta_get_user_details") process.exit(0); // Not this step's action: emit nothing.

const base = process.env.OKTA_ORG_URL!.replace(/\/$/, "");
const login = ctx.case.metadata?.email ?? ctx.case.metadata?.username;
const emit = (success: boolean, response: unknown) =>
  console.log(JSON.stringify({ context: ctx, result: { system: "Okta", target: login ?? null, success, response } }));

if (!login) {
  console.error(JSON.stringify({ event: "missing_target", case_id: ctx.case.id }));
  emit(false, { error: "Case metadata has no 'email' or 'username' to identify the Okta user." });
  process.exit(0);
}

const res = await fetch(`${base}/api/v1/users/${encodeURIComponent(login)}`, { headers: { accept: "application/json" } });
const user: any = await res.json().catch(() => ({}));
console.error(JSON.stringify({ event: "okta_get_user", status: res.status, case_id: ctx.case.id }));
if (!res.ok) {
  emit(false, { status: res.status, body: user });
  process.exit(0);
}
const p = user.profile ?? {};
emit(true, {
  id: user.id,
  status: user.status,
  login: p.login,
  name: [p.firstName, p.lastName].filter(Boolean).join(" "),
  email: p.email,
  title: p.title ?? null,
  department: p.department ?? null,
  manager: p.manager ?? null,
  mobilePhone: p.mobilePhone ?? null,
  created: user.created,
  activated: user.activated,
  lastLogin: user.lastLogin,
  lastUpdated: user.lastUpdated,
  passwordChanged: user.passwordChanged,
  statusChanged: user.statusChanged,
});
