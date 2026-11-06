// Comments on the case that the action was initiated, then removes the clicked case action button.
const ctx = JSON.parse(await Bun.stdin.text());
// Normalize TINES_URL, tolerating a duplicated or missing scheme (e.g. "https://https//host").
const base = "https://" + process.env.TINES_URL!.trim().replace(/^(https?:?\/*)+/i, "").replace(/\/+$/, "");
const caseId = ctx.case.id;

const commentRes = await fetch(`${base}/api/v2/cases/${caseId}/comments`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    value: `⚡ Case action **${ctx.label}** was initiated by <@user-${ctx.user.id}> (${ctx.user.name}).`,
  }),
});
if (!commentRes.ok) {
  console.error(JSON.stringify({ event: "comment_failed", case_id: caseId, status: commentRes.status, body: (await commentRes.text()).slice(0, 500) }));
  process.exit(1);
}

const delRes = await fetch(`${base}/api/v2/cases/${caseId}/actions/${ctx.button_id}`, { method: "DELETE" });
// 404 means the button is already gone (e.g. a double click); treat as removed.
if (!delRes.ok && delRes.status !== 404) {
  console.error(JSON.stringify({ event: "action_delete_failed", case_id: caseId, button_id: ctx.button_id, status: delRes.status, body: (await delRes.text()).slice(0, 500) }));
  process.exit(1);
}

console.error(JSON.stringify({ event: "case_acknowledged", case_id: caseId, button_id: ctx.button_id, delete_status: delRes.status }));
console.log(JSON.stringify(ctx));
