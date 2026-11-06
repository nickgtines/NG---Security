Services **Case Actions** clicked in Tines Cases. A Tines case action of type `webhook` posts to the **Case Actions webhook**; the button's `label` decides which action runs.

**Flow:** Receive Case Action → Acknowledge in Case (comment "initiated by <user>" + remove the clicked button) → matching action step → Record Result in Case (note with action, actor, and endpoint response).

| Case action label | Step | System |
| --- | --- | --- |
| `Contain Host` | CrowdStrike Contain Host | CrowdStrike (mocked) |
| `Kill Process` | CrowdStrike Kill Process | CrowdStrike (mocked) |
| `Revoke Sessions` | Okta Revoke Sessions | Okta |
| `Suspend User` | Okta Suspend User | Okta |
| `Force Password Reset` | Okta Require Password Reset | Okta |
| `Create Slack Channel` | Slack Create Channel | Slack |
| `Get User Details` | Okta Get User Details | Okta (read-only) |

Labels match case-insensitively. Unknown labels fail the run in the receiver without touching the case. To add an action: add its label to `ACTIONS` in `Receive Case Action/script.ts`, create a step that checks for the new action key, link it from **Acknowledge in Case**, and link it to **Record Result in Case**.

**Case metadata used:** `email`/`username` (Okta target), `hostname`/`host`/`device_id` (CrowdStrike host), `process_name`/`process_id`/`sha256` (CrowdStrike process).

Action steps emit `{ context, result: { system, target, success, response } }`. A failed endpoint call is still noted in the case (red note), and then the run is marked failed.
