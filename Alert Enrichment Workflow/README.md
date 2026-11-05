Alert Enrichment — a reusable component of the Alert Orchestrator (alert record contract v3).

**POST /enrich** (workflow-connector auth) takes an alert record, fills in only `enrichment` and appends one `trace` entry, then returns the full record. It never changes any other section. Valid input always gets `200`, with errors recorded in the record; input that doesn't match the contract gets `400`.

- **IOC reputation:** GreyNoise and AbuseIPDB (IPs), VirusTotal (all types), urlscan.io (URLs and domains; searches existing scans only). Private, loopback and link-local IPs are skipped, with a limit of 25 IOCs per alert. Results are cached for 24 hours per provider + IOC.
- **Entity context (read-only):** Okta user (status, groups, MFA factors, last 10 sign-ins) and CrowdStrike host (platform, last seen, sensor, tags, containment status).
- **Steps:** Enrich (core) → Write audit record. Enrich test (`/enrich/test`) runs a sample record. Lookup page (`/lookup`) and Lookup API look up one IOC by hand. Cache cleanup runs hourly.
- All thresholds are in `Enrich/config.ts`.
