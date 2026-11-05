`POST /investigate` (route_auth `connector`: called by the Alert Orchestrator via a workflow connector). Body is an Alert Record v3. Fills in only `investigation`, appends one `trace` entry, returns the full record.

- `investigation.py`: `CODE_VERSION`, `PRIVILEGED_GROUPS`, the six `check_*` functions, the `external_findings` hook, `decide_verdict`.
- 400 for invalid JSON or contract mismatch; check errors are captured in an info finding and the trace `error`, never 500.
- Logs are single-line JSON on stderr with `correlation_id`, one "cell" per function (input summary, each check's output, verdict).
