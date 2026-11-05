Alert Investigation — reusable component of the Alert Orchestrator pipeline (Alert Record contract v3). Replaces the investigation Jupyter notebook with pure, deterministic Python: no external calls, no AI.

- **Investigate** — `POST /investigate`, the connector-authenticated API the Orchestrator calls.
- **Test** — `GET /test`, runs three sample records and shows their findings.
