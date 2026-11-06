import { readdirSync, statSync } from "node:fs";
import {
  Answer, CLOSED_DIR, ID_RE, OPEN_DIR, RESPONSES_DIR, Reachout, ResponseRecord, closeRecord, commentOnCase, esc, log,
  parseHttp, readJson, removeIfExists, slack, threadReply, tines,
} from "./lib.ts";

const ANSWER_LABEL: Record<Answer, string> = {
  confirmed: "Confirmed: \"Yes, this was me\"",
  denied: "Denied: \"No, this wasn't me\"",
  no_response: "No response",
};
const TAG: Record<Answer, string> = {
  confirmed: "user-confirmed-activity",
  denied: "user-denied-activity",
  no_response: "user-no-response",
};
const PRIORITIES = ["info", "low", "medium", "high", "critical"];
const SWEEP_BATCH = 25;
const STUCK_RESPONSE_MS = 5 * 60_000;
const CLOSED_RETENTION_MS = 30 * 24 * 60 * 60_000;

async function finalize(rec: Reachout, answer: Answer, at: string) {
  const cid = rec.correlation_id;
  log(cid, "finalize_start", { reachout_id: rec.reachout_id, answer });

  // 4. Update the DM: show the answer, remove the buttons.
  if (rec.dm_channel && rec.dm_ts) {
    const resultText =
      answer === "confirmed"
        ? ":white_check_mark: You answered *Yes, this was me*. Thanks, the security team has been updated."
        : answer === "denied"
          ? ":rotating_light: You answered *No, this wasn't me*. The security team has been alerted and will follow up."
          : `:hourglass: No answer was received within ${rec.timeout_minutes} minutes. The security team may follow up.`;
    await slack(
      "chat.update",
      {
        channel: rec.dm_channel,
        ts: rec.dm_ts,
        text: `Security check: ${ANSWER_LABEL[answer]}`,
        blocks: [
          { type: "header", text: { type: "plain_text", text: "Security check", emoji: true } },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `The security team is checking some activity on your account.\n*Alert:* ${esc(rec.alert_title)}`,
            },
          },
          { type: "section", text: { type: "mrkdwn", text: `*${esc(rec.question)}*` } },
          { type: "section", text: { type: "mrkdwn", text: resultText } },
          { type: "context", elements: [{ type: "mrkdwn", text: `Recorded ${at}` }] },
        ],
      },
      cid,
    );
  }

  // 5. Comment on the case.
  await commentOnCase(
    rec,
    [
      "**Security reachout — user response**",
      `- **User:** ${rec.user_upn}${rec.slack_user_id ? ` (Slack ${rec.slack_user_id})` : ""}`,
      `- **Question:** ${rec.question}`,
      `- **Answer:** ${ANSWER_LABEL[answer]}`,
      `- **Time:** ${at}`,
      `- **Reachout ID:** ${rec.reachout_id}`,
    ].join("\n"),
  );

  // Tags (and priority bump on denial).
  const update: Record<string, unknown> = { add_tag_names: [TAG[answer]] };
  if (answer === "denied") {
    const c = await tines("GET", `/api/v2/cases/${encodeURIComponent(rec.case_id)}`, cid);
    const current = String(c?.priority ?? "").toLowerCase();
    const idx = PRIORITIES.indexOf(current);
    const next = PRIORITIES[Math.min(Math.max(idx, 0) + 1, PRIORITIES.length - 1)];
    if (next !== current) update.priority = next;
    log(cid, "case_priority", { from: current || null, to: next });
  }
  await tines("PUT", `/api/v2/cases/${encodeURIComponent(rec.case_id)}`, cid, update);

  // Thread reply in the alert channel.
  const caseLink = `<${rec.case_url}|Case ${esc(rec.case_id)}>`;
  const reply =
    answer === "denied"
      ? `:rotating_light: User denied the activity\n${esc(rec.user_upn)} answered "No, this wasn't me". ${caseLink} priority raised.`
      : answer === "confirmed"
        ? `:white_check_mark: User confirmed the activity\n${esc(rec.user_upn)} answered "Yes, this was me". ${caseLink} updated.`
        : `:hourglass: No response from ${esc(rec.user_upn)} within ${rec.timeout_minutes} minutes. ${caseLink} updated.`;
  await threadReply(rec, reply);

  closeRecord(rec, answer);
}

const raw = await Bun.stdin.text();

if (raw.trim()) {
  // Linked from "Slack interactivity": finalize the clicked reachout.
  const id = parseHttp(raw).headers["x-reachout-id"];
  if (!id || !ID_RE.test(id)) process.exit(0); // click was ignored upstream
  const rec = readJson<Reachout>(`${OPEN_DIR}/${id}.json`);
  const resp = readJson<ResponseRecord>(`${RESPONSES_DIR}/${id}.json`);
  if (!rec || !resp) {
    log(rec?.correlation_id, "finalize_skipped_missing", { reachout_id: id });
    process.exit(0);
  }
  await finalize(rec, resp.answer, resp.responded_at);
} else {
  // Scheduled sweep: expire timed-out reachouts, retry stuck answers, prune old closed records.
  const now = Date.now();
  const ids = (() => {
    try {
      return readdirSync(OPEN_DIR).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).filter((i) => ID_RE.test(i));
    } catch {
      return [] as string[];
    }
  })();
  let handled = 0;
  let failures = 0;
  for (const id of ids) {
    if (handled >= SWEEP_BATCH) break;
    const rec = readJson<Reachout>(`${OPEN_DIR}/${id}.json`);
    if (!rec) continue;
    const resp = readJson<ResponseRecord>(`${RESPONSES_DIR}/${id}.json`);
    try {
      if (resp) {
        if (now - Date.parse(resp.responded_at) < STUCK_RESPONSE_MS) continue; // click run is handling it
        log(rec.correlation_id, "sweep_retry_answer", { reachout_id: id });
        handled++;
        await finalize(rec, resp.answer, resp.responded_at);
      } else if (rec.status === "sent" && now > Date.parse(rec.deadline_at)) {
        handled++;
        await finalize(rec, "no_response", new Date().toISOString());
      } else if (rec.status === "pending" && now - Date.parse(rec.created_at) > 15 * 60_000) {
        // DM was never sent (Send DM failed). Record it instead of leaving it open forever.
        handled++;
        log(rec.correlation_id, "sweep_unsent_reachout", { reachout_id: id });
        await commentOnCase(
          rec,
          `**Security reachout — failed**\n- **User:** ${rec.user_upn}\n- **Question:** ${rec.question}\n- **Time:** ${new Date().toISOString()}\n- **Reachout ID:** ${id}\n\nThe Slack DM could not be sent. Follow up manually.`,
        );
        closeRecord(rec, "no_response");
      }
    } catch (err) {
      failures++;
      log(rec.correlation_id, "sweep_finalize_failed", { reachout_id: id, error: String(err) });
    }
  }
  try {
    for (const f of readdirSync(CLOSED_DIR)) {
      const p = `${CLOSED_DIR}/${f}`;
      if (now - statSync(p).mtimeMs > CLOSED_RETENTION_MS) removeIfExists(p);
    }
  } catch {
    /* closed/ does not exist yet */
  }
  if (handled || failures) log(null, "sweep_done", { open: ids.length, handled, failures });
  if (failures) process.exit(1);
}
