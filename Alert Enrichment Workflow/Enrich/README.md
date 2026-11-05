Core of Alert Enrichment. Receives an alert record (schema v3) and fills in only `enrichment`, appends one `trace` entry, and returns the full record.

- **Trigger:** `POST /enrich` (workflow-connector auth, for the Alert Orchestrator), or linked from **Enrich test** / **Lookup API**.
- **IOC reputation:** `adapters.ts` — `lookup_greynoise`, `lookup_abuseipdb`, `lookup_virustotal`, `lookup_urlscan` (searches existing scans only).
- **Entity context:** `entities.ts` — `lookup_okta_user`, `lookup_crowdstrike_host` (GET requests only; never contains a host).
- **Thresholds and limits:** `config.ts` CONFIG block.
- All lookups run in parallel with an 8 s per-call timeout. Timeouts, errors and 429s become `error` + verdict `unknown`.
- IOC results are cached in the `ioc-cache` volume for 24 h per provider + IOC (errors are never cached). Each run writes new uniquely-named files; **Cache cleanup** deletes expired ones.
- Invalid input → `400`. Valid input always → `200` with the record, errors recorded in `enrichment` and the trace entry.
- A body of `{"lookup":{"ioc":"..."}}` runs a single IOC through every applicable provider (used by the /lookup page).
