import {
  ID_RE, OPEN_DIR, Reachout, SlackApiError, closeRecord, commentOnCase, esc, log, parseHttp, readJson, slack,
  threadReply, writeJson,
} from "./lib.ts";

// stdin is the 202 response produced by "Receive reachout".
const res = parseHttp(await Bun.stdin.text());
if (!res.startLine.includes(" 202 ")) process.exit(0); // validation failures: nothing to do
const { reachout_id } = JSON.parse(res.body);
if (typeof reachout_id !== "string" || !ID_RE.test(reachout_id)) throw new Error("Invalid reachout_id from intake");

const path = `${OPEN_DIR}/${reachout_id}.json`;
const rec = readJson<Reachout>(path);
if (!rec) throw new Error(`No open reachout ${reachout_id}`);
const cid = rec.correlation_id;
if (rec.status !== "pending") {
  log(cid, "dm_already_sent", { reachout_id });
  process.exit(0);
}

// 1. Look up the Slack user by email.
let slackUser: any = null;
const lookup = await fetch(`https://slack.com/api/users.lookupByEmail?email=${encodeURIComponent(rec.user_upn)}`);
const lookupJson: any = await lookup.json();
if (lookupJson.ok && lookupJson.user && !lookupJson.user.deleted) slackUser = lookupJson.user;
else if (lookupJson.ok || lookupJson.error === "users_not_found") slackUser = null;
else {
  log(cid, "slack_api_error", { method: "users.lookupByEmail", error: lookupJson.error });
  throw new SlackApiError("users.lookupByEmail", String(lookupJson.error));
}

if (!slackUser) {
  log(cid, "slack_user_not_found", { reachout_id, user_upn: rec.user_upn });
  await commentOnCase(
    rec,
    [
      "**Security reachout — Slack user not found**",
      `- **User:** ${rec.user_upn}`,
      `- **Question (not sent):** ${rec.question}`,
      `- **Time:** ${new Date().toISOString()}`,
      `- **Reachout ID:** ${rec.reachout_id}`,
      "",
      "No active Slack account matches this email, so the user could not be asked. Follow up through another channel.",
    ].join("\n"),
  );
  await threadReply(
    rec,
    `:warning: Could not reach ${esc(rec.user_upn)}: no matching Slack user. <${rec.case_url}|Case ${esc(rec.case_id)}> updated.`,
  );
  closeRecord(rec, "user_not_found");
  process.exit(0);
}

// 2. Send the Block Kit DM. Posting to the user ID delivers it to the app's
// Messages tab and only needs chat:write (no im:write / conversations.open).
const blocks = [
  { type: "header", text: { type: "plain_text", text: "Security check", emoji: true } },
  {
    type: "section",
    text: {
      type: "mrkdwn",
      text: `The security team is checking some activity on your account.\n*Alert:* ${esc(rec.alert_title)}`,
    },
  },
  { type: "section", text: { type: "mrkdwn", text: `*${esc(rec.question)}*` } },
  {
    type: "actions",
    block_id: "reachout_answer",
    elements: [
      {
        type: "button",
        action_id: "reachout_confirm",
        style: "primary",
        text: { type: "plain_text", text: "Yes, this was me" },
        value: rec.reachout_id,
      },
      {
        type: "button",
        action_id: "reachout_deny",
        style: "danger",
        text: { type: "plain_text", text: "No, this wasn't me" },
        value: rec.reachout_id,
      },
    ],
  },
];
const msg = await slack(
  "chat.postMessage",
  { channel: slackUser.id, text: `Security check: ${rec.question}`, blocks },
  cid,
);

const sent: Reachout = {
  ...rec,
  status: "sent",
  slack_user_id: slackUser.id,
  dm_channel: msg.channel,
  dm_ts: msg.ts,
  sent_at: new Date().toISOString(),
};
writeJson(path, sent);
log(cid, "dm_sent", { reachout_id, slack_user_id: slackUser.id, deadline_at: rec.deadline_at });
