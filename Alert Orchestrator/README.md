Alert Orchestrator ingests security alerts, normalizes them into the shared alert record (contract v3), and coordinates the Alert Triage, Alert Enrichment, Alert Investigation and Alert Response workflows synchronously through workflow connectors. Fully deterministic — no AI at runtime.

- `POST /ingest/sentinel`, `POST /ingest/crowdstrike` (space auth) → normalize → **Call Alert Triage** → **Call Alert Enrichment** → **Call Alert Investigation** → **Call Alert Response** → returns the final record (or 400). Each step uses only its own workflow connector; Enrichment and Investigation pass the record through untouched for SUPPRESS_DUPLICATE / DISMISS_KNOWN_GOOD.
- Final records are stored in volume `alert-orchestrator-runs`, keyed by correlation_id; `GET /runs` lists them.
- `/` is a demo page with five sample payloads.

#### End-to-end flow

```mermaid
flowchart TD
    Demo["Demo page (GET /)<br/>Sends sample alerts, shows trace,<br/>case and Slack links, recent runs"]
    SEN["Ingest Sentinel<br/>POST /ingest/sentinel<br/>Normalize Sentinel alert/incident,<br/>extract and dedupe IOCs, build v3 record"]
    CS["Ingest CrowdStrike<br/>POST /ingest/crowdstrike<br/>Normalize Falcon detection,<br/>extract and dedupe IOCs, build v3 record"]
    TRI["Call Alert Triage<br/>Add ingest trace, POST /triage<br/>to Alert Triage workflow"]
    D{"Triage verdict?"}
    ENR["Call Alert Enrichment<br/>POST /enrich: threat intel<br/>and context on IOCs"]
    INV["Call Alert Investigation<br/>POST /investigate: correlate<br/>and assess the alert"]
    PASS["Pass record through unchanged"]
    RESP["Call Alert Response<br/>POST /respond: case + Slack,<br/>add orchestrator trace entry"]
    VOL[("Volume alert-orchestrator-runs<br/>records/&lt;correlation_id&gt;.json + index")]
    OUT["HTTP response<br/>Final record, or 400 if invalid"]
    RUNS["Runs API<br/>GET /runs: recent summaries<br/>GET /runs?id=: full record"]

    Demo -->|sample payloads| SEN
    Demo -->|sample payloads| CS
    SEN --> TRI
    CS --> TRI
    TRI --> D
    D -->|INVESTIGATE / TRIAGE_ERROR| ENR
    ENR --> INV
    D -->|SUPPRESS_DUPLICATE / DISMISS_KNOWN_GOOD| PASS
    PASS --> RESP
    INV --> RESP
    RESP --> VOL
    RESP --> OUT
    VOL --> RUNS
    RUNS -->|recent runs| Demo
```

Each component call has a 30 s timeout; on failure the last good record is kept and a `call_failed` trace entry is added. Invalid ingest input skips the component calls and returns 400.

`run_url` is filled from `_3B_RUN_URL` when the platform provides it, otherwise null.
