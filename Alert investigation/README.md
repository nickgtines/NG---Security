Alert Investigation is a reusable part of the Alert Orchestrator pipeline (Alert Record contract v3). It replaces the investigation Jupyter notebook with pure, deterministic Python: no external calls, no AI, no randomness. All time comparisons use timestamps inside the record, so the same input always gives the same output.

- **Investigate**: `POST /investigate`, the connector-authenticated API the Orchestrator calls. It reads `alert` and `enrichment`, fills in only `investigation`, and appends one `trace` entry.
- **Test**: `GET /test` runs three sample records (escalate, needs_user_confirmation, benign) and shows their findings.

#### Checks

Every check runs on every record. A check only produces a finding when its condition is met. A check that has no data to work with (for example, no sign-in evidence or no host context) stays silent.

| Check | Fires when | Severity | Why |
|---|---|---|---|
| `check_ioc_reputation` | Any `enrichment.ioc_results` entry has verdict `malicious` (if none, `suspicious`) | high (malicious) / medium (suspicious) | Threat intel has already linked an indicator in the alert to known-bad activity. This is the strongest signal of real compromise. |
| `check_impossible_travel` | Two sign-ins from different countries within **2 hours**. Uses both the alert's sign-in evidence and the user's recent Okta logins. | medium | Nobody can travel between countries that fast. The usual cause is a stolen credential or session used from somewhere else, though VPNs can trigger it too, so the user is asked to confirm. |
| `check_signin_risk` | Any of: (1) one or more failed sign-ins followed by a success, (2) legacy/basic authentication (IMAP, POP, SMTP, ActiveSync, EWS, etc., or `legacy_auth: true`), (3) a sign-in from a country that doesn't appear in the user's recent Okta logins (only checked when that history exists) | medium | (1) can mean password guessing or spraying that worked. (2) skips MFA and is a common way attackers get in. (3) is a departure from the user's normal locations. |
| `check_suspicious_process` | A `process` evidence command line matches a living-off-the-land pattern: encoded PowerShell, `certutil -urlcache`, `rundll32` with a URL/UNC path, or `mshta` loading over HTTP | high | Attackers use these built-in Windows tools to download or run payloads while avoiding detection. Legitimate use is rare. |
| `check_privileged_user` | The user belongs to a group in `PRIVILEGED_GROUPS` (Domain Admins, Global Administrators, Okta Super Admins, AWS-Admins, Security-Admins, IT-Admins) | info | Taking over an admin account causes much more damage, so admin accounts are held to a stricter standard (see uplift below). |
| `check_host_posture` | The host isn't found in CrowdStrike, or CrowdStrike last saw it more than **7 days** before the alert's `last_seen`. Skipped if host context is missing or returned an error. | low | An unmanaged or stale host has no working EDR coverage. That means less visibility and a higher chance something was missed. |
| `external_findings` (hook) | Reserved for findings from other internal components. It currently returns none. | as supplied | Lets other components add to the verdict without changing this module. |

If a check fails with an error, the investigation keeps going. The error is recorded as an `info` finding and in the trace entry's `error`.

#### Privilege uplift

If `check_privileged_user` fires, every other `low` finding becomes `medium` and every `medium` becomes `high`. `high` stays `high`. The finding keeps its earlier level in `original_severity`. As a result, any medium finding for an admin (such as impossible travel) leads to escalation.

#### Risk score

After uplift, each finding adds a weight based on its severity:

| Severity | Weight |
|---|---|
| info | 0 |
| low | 10 |
| medium | 25 |
| high | 40 |

`risk_score = min(100, sum of weights)`. For example, a suspicious IOC (25) plus a stale host (10) gives 35. A malicious IOC (40), a LOLBin process (40) and impossible travel (25) gives 105, which is capped at 100.

#### Verdict

The risk score is reported for context. The verdict depends on the findings' severities, not on the score:

1. **escalate**: any finding is `high`.
2. **needs_user_confirmation**: otherwise, if `check_impossible_travel` or `check_signin_risk` fired. A `confirmation_question` is built from the most recent unusual sign-in in the alert, for example: *"Did you sign in to Salesforce (via Okta) from Germany on Wednesday, November 4, 2026 at 14:22 UTC?"* Country codes are written out as names, and the app or identity provider is included when known. If no dated sign-in is available, it asks a generic question about an unfamiliar location.
3. **benign**: everything else (including only low/info findings).

If the verdict itself can't be computed, the record fails safe to `escalate` with `risk_score` 100.
