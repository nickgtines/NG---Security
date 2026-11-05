Alert Response component (alert record contract v3). The Alert Orchestrator calls `POST /respond` synchronously through a workflow connector; it fills in only `case` and `response`, appends one `trace` entry, and returns the full record. Deterministic, no AI.

**By `triage.disposition`:**
- `SUPPRESS_DUPLICATE` → comment on `triage.matched_case_id`; `case` set to that case; no Slack.
- `DISMISS_KNOWN_GOOD` → create a closed case tagged `known-good` with the allowlist entry; one line to `#soc-log`.
- `INVESTIGATE` / `TRIAGE_ERROR` → create a case (tags `dedup:`, `source:`, `severity:`, `verdict:`, `automation-error`; Triage, Enrichment, Investigation, Alert sections), Block Kit to `#soc-alerts` with a View case button and error warning. If verdict is `needs_user_confirmation`, calls Security Reachout `POST /reachout` (expects 202) → `reachout_sent`.

Failures are recorded in `response.errors` and the trace entry `error`; valid input never gets a 500. Invalid input → 400. Alert Triage dedups by searching case tags, so no `/dedup-index` call is made (set `triage_dedup_index_url` to enable it).

Config: `Respond/config.json` (team, channel names). Test: `GET /respond/test` runs `Respond test/sample.json`.
