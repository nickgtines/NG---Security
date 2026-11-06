`GET /respond/test` runs the bundled `sample.json` (INVESTIGATE / needs_user_confirmation) through the same logic as `/respond` — it creates a real Tines case, posts to Slack and starts a reachout. `POST` with a record runs that record instead. Keep `respond.ts`/`config.json` in sync with the Respond step.

#### Case layout
The case description holds only the alert context table and the automation trace. Triage (blue), Enrichment (indigo) and Investigation (gold for needs user confirmation, red for escalate, green for benign) are added as separate case notes. API responses are summarized into readable tables (sign-ins, IOC highlights per provider) rather than raw JSON. Formatting lives in `format.ts`.
