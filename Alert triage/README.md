Reusable **Alert Triage** component (alert record contract v3). The Alert Orchestrator calls `POST /triage` synchronously through a workflow connector; the response is the full record with only `triage` filled in and one `trace` entry appended.

**Checks (always all three, in order):**
1. `known_good_list_check` – user UPN / hostname vs. the known-good list in the `known-good` volume (expired entries ignored). Manage it at `/known-good`.
2. `known_good_okta_check` – Okta membership in `SOC-KnownGood-ServiceAccounts`. User not found → `no_match`.
3. `duplicate_check` – open Tines cases tagged `dedup:<dedup_key>` created in the last 24h, via `POST /api/v3/cases/search` (supports tag + status + created_at filters, so no local dedup index or `/dedup-index` route is needed).

**Disposition:** known-good → `DISMISS_KNOWN_GOOD`; else duplicate → `SUPPRESS_DUPLICATE`; else any check error → `TRIAGE_ERROR` (fail open); else `INVESTIGATE`. Invalid input → 400; errors never produce 500.

Config (`Triage/config.json`): `okta_known_good_group`, `dedup_window_hours`. Logs are JSON lines with `correlation_id` and `run_id`. `run_url` is `null` because 3B doesn't expose a run URL to step code.

Test: `GET /triage/test` runs the bundled sample record; `POST /triage/test` runs any record you send.
