import { ID_RE, OPEN_DIR, RESPONSES_DIR, Reachout, ResponseRecord, httpResponse, log, parseHttp, readJson, writeJson } from "./lib.ts";

// Slack must get a 200 within 3 seconds, so this step only records the click.
// "Finalize reachout" does the Slack/Tines work downstream.
const req = parseHttp(await Bun.stdin.text());
const ack = (headers: Record<string, string> = {}) => process.stdout.write(httpResponse(200, "OK", "", headers));

let payload: any = null;
try {
  const form = new URLSearchParams(req.body);
  payload = JSON.parse(form.get("payload") ?? "");
} catch {
  log(null, "interaction_unparseable");
}

const action = payload?.type === "block_actions" ? payload.actions?.[0] : null;

// "Close Case" button: the case ID comes from the button value or the message it sits in.
const isCloseCase =
  action?.action_id === "close_case" ||
  (action?.type === "button" && String(action?.text?.text ?? "").trim().toLowerCase() === "close case");
if (isCloseCase) {
  const fromValue = typeof action.value === "string" && /^\d{1,18}$/.test(action.value.trim()) ? action.value.trim() : null;
  const haystack = [payload.message?.text ?? "", JSON.stringify(payload.message?.blocks ?? [])].join("\n");
  const m =
    haystack.match(/\/cases\/(\d{1,18})/i) ??
    haystack.match(/case[\s_-]*(?:id)?[\s:*#|]*(\d{1,18})/i);
  const caseId = fromValue ?? m?.[1] ?? null;
  const channel = payload.channel?.id ?? payload.container?.channel_id ?? "";
  const ts = payload.container?.message_ts ?? payload.message?.ts ?? "";
  if (!caseId) {
    log(null, "close_case_no_case_id", { channel, message_ts: ts });
    ack();
    process.exit(0);
  }
  log(null, "close_case_requested", { case_id: caseId, clicker: payload.user?.id ?? null });
  // The original message minus the Close Case button, so Finalize can update it in place.
  const isCloseBtn = (el: any) =>
    el?.action_id === "close_case" ||
    (el?.type === "button" && String(el?.text?.text ?? "").trim().toLowerCase() === "close case");
  const blocks = (Array.isArray(payload.message?.blocks) ? payload.message.blocks : [])
    .map((b: any) => (b?.type === "actions" && Array.isArray(b.elements) ? { ...b, elements: b.elements.filter((e: any) => !isCloseBtn(e)) } : b))
    .filter((b: any) => !(b?.type === "actions" && b.elements.length === 0))
    .map((b: any) => (b?.type === "section" && isCloseBtn(b.accessory) ? (({ accessory, ...rest }) => rest)(b) : b));
  const body = JSON.stringify({ text: String(payload.message?.text ?? ""), blocks });
  process.stdout.write(httpResponse(200, "OK", body, {
    "content-type": "application/json",
    "x-close-case-id": caseId,
    "x-slack-channel": /^[A-Z0-9]+$/.test(channel) ? channel : "",
    "x-slack-message-ts": /^\d+\.\d+$/.test(ts) ? ts : "",
    "x-slack-user": /^[A-Z0-9]+$/.test(payload.user?.id ?? "") ? payload.user.id : "",
  }));
  process.exit(0);
}
const answer =
  action?.action_id === "reachout_confirm" ? "confirmed" : action?.action_id === "reachout_deny" ? "denied" : null;
const reachoutId = typeof action?.value === "string" && ID_RE.test(action.value) ? action.value : null;

if (!answer || !reachoutId) {
  log(null, "interaction_ignored", { type: payload?.type ?? null, action_id: action?.action_id ?? null });
  ack();
  process.exit(0);
}

const rec = readJson<Reachout>(`${OPEN_DIR}/${reachoutId}.json`);
if (!rec || rec.status !== "sent") {
  log(rec?.correlation_id, "interaction_no_open_reachout", { reachout_id: reachoutId });
  ack();
  process.exit(0);
}
const cid = rec.correlation_id;

// Only the user who was asked, on the message we sent, may answer.
if (payload.user?.id !== rec.slack_user_id || payload.container?.message_ts !== rec.dm_ts) {
  log(cid, "interaction_rejected_mismatch", { reachout_id: reachoutId, clicker: payload.user?.id ?? null });
  ack();
  process.exit(0);
}
if (Date.now() > Date.parse(rec.deadline_at)) {
  log(cid, "interaction_after_deadline", { reachout_id: reachoutId });
  ack();
  process.exit(0);
}
const responsePath = `${RESPONSES_DIR}/${reachoutId}.json`;
if (readJson(responsePath)) {
  log(cid, "interaction_duplicate", { reachout_id: reachoutId });
  ack();
  process.exit(0);
}

const response: ResponseRecord = {
  reachout_id: reachoutId,
  answer,
  slack_user_id: payload.user.id,
  responded_at: new Date().toISOString(),
};
writeJson(responsePath, response);
log(cid, "interaction_recorded", { reachout_id: reachoutId, answer });
ack({ "x-reachout-id": reachoutId });
