Asks an affected user to confirm suspicious activity in a Slack DM and writes the answer back to the Tines case. Fully deterministic, no AI.

**Flow**
1. `POST /reachout` (connector auth: called only by workflows that have the Security Reachout connector attached) validates the input, stores an open reachout in the `reachouts` volume, and returns `202 {reachout_id}` straight away.
2. **Send DM** looks up the Slack user by `user_upn` and sends a Block Kit DM with "Yes, this was me" / "No, this wasn't me". If no user is found, it comments on the case and replies in the alert thread.
3. **Slack interactivity** receives the button click (Slack app Interactivity Request URL), checks it came from the asked user before the deadline, and records it.
4. **Finalize reachout** updates the DM (buttons removed), comments on the case, tags it (`user-confirmed-activity` / `user-denied-activity` + priority bump / `user-no-response`), and replies in `slack_channel`/`slack_thread_ts`. It also runs every minute to expire unanswered reachouts as `no_response`.

Every log line is JSON on stderr with `correlation_id`.

**Storage** (`reachouts` volume): `open/<id>.json`, `responses/<id>.json`, `closed/<id>.json` (kept 30 days).
