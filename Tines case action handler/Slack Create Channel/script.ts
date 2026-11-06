// Creates a Slack incident channel for the case and invites the analyst who clicked the action.
const ctx = JSON.parse(await Bun.stdin.text());
if (ctx.action !== "slack_create_channel") process.exit(0); // Not this step's action: emit nothing.

const slack = async (method: string, body: Record<string, unknown>) => {
  const res = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
  return res.json() as Promise<any>;
};

// Slack channel names: lowercase, max 80 chars, letters/digits/-/_ only.
const slug = String(ctx.case.name ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const name = `case-${ctx.case.id}-${slug}`.slice(0, 80).replace(/-$/, "");

const created = await slack("conversations.create", { name, is_private: false });
const emit = (success: boolean, response: unknown) =>
  console.log(JSON.stringify({ context: ctx, result: { system: "Slack", target: `#${name}`, success, response } }));

if (!created.ok) {
  console.error(JSON.stringify({ event: "slack_create_failed", error: created.error, case_id: ctx.case.id }));
  emit(false, { step: "conversations.create", ...created });
  process.exit(0);
}
const channel = created.channel;

await slack("conversations.setTopic", { channel: channel.id, topic: `Tines case ${ctx.case.id}: ${ctx.case.url}` });

let invite: unknown = { skipped: "no user email" };
if (ctx.user.email) {
  const lookup = await fetch(`https://slack.com/api/users.lookupByEmail?email=${encodeURIComponent(ctx.user.email)}`).then((r) => r.json() as Promise<any>);
  invite = lookup.ok
    ? await slack("conversations.invite", { channel: channel.id, users: lookup.user.id }).then((r) => ({ ok: r.ok, error: r.error }))
    : { ok: false, error: lookup.error };
}

console.error(JSON.stringify({ event: "slack_channel_created", channel_id: channel.id, name: channel.name, case_id: ctx.case.id }));
emit(true, { channel_id: channel.id, channel_name: channel.name, created: channel.created, invite });
