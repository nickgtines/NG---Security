// Adds a case note describing the action taken, who took it, and the endpoint system's response.
const { context: ctx, result } = JSON.parse(await Bun.stdin.text());
const base = process.env.TINES_URL!.replace(/\/$/, "");

const statusText = result.success ? "✅ Succeeded" : "❌ Failed";
const content = [
  `**Action:** ${ctx.label}`,
  `**System:** ${result.system}`,
  `**Target:** ${result.target ?? "n/a"}`,
  `**Taken by:** ${ctx.user.name}${ctx.user.email ? ` (${ctx.user.email})` : ""}`,
  `**Status:** ${statusText}`,
  `**Completed at:** ${new Date().toISOString()}`,
  "",
  "**Response:**",
  "```json",
  JSON.stringify(result.response, null, 2).slice(0, 8000),
  "```",
].join("\n");

const res = await fetch(`${base}/api/v2/cases/${ctx.case.id}/notes`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    title: `${result.success ? "✅" : "❌"} ${ctx.label} — ${result.system}`,
    content,
    color: result.success ? "green" : "red",
  }),
});
if (!res.ok) {
  console.error(JSON.stringify({ event: "note_failed", case_id: ctx.case.id, status: res.status, body: (await res.text()).slice(0, 500) }));
  process.exit(1);
}
const note = await res.json();
console.error(JSON.stringify({ event: "note_added", case_id: ctx.case.id, note_id: note.id, action: ctx.action, success: result.success }));
console.log(JSON.stringify({ case_id: ctx.case.id, note_id: note.id, action: ctx.action, success: result.success }));
// Surface failed endpoint actions as a failed run after documenting them in the case.
if (!result.success) process.exit(1);
