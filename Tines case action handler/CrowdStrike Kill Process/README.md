**Mocked.** Simulates a CrowdStrike Real Time Response `kill` command. No real API call is made.

**Expected case action label:** `Kill Process`

Runs only for action key `crowdstrike_kill_process`. Host from metadata `hostname`/`host`/`device_id`; process from `process_name`/`process_id`/`sha256`.
