`POST /respond` — takes a completed alert record (contract v3), performs case + Slack actions based on `triage.disposition`, fills in `case` and `response`, appends one `trace` entry, and returns the full record. Invalid input → 400; action failures are recorded in `response.errors` and the trace entry, never 500.

Config (`config.json`): `tines_team_id`, `slack_alerts_channel`, `slack_log_channel`, `case_actions_webhook_url` (Case Action webhook), `triage_dedup_index_url` (null: Alert Triage searches cases by `dedup:` tag, so no index registration is needed).
