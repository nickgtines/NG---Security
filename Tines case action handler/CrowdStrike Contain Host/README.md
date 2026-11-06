**Mocked.** Simulates CrowdStrike Falcon network containment of a host. No real API call is made; the response mirrors `POST /devices/entities/devices-actions/v2?action_name=contain`.

**Expected case action label:** `Contain Host`

Runs only for action key `crowdstrike_contain_host`. Host comes from case metadata `hostname`, `host`, or `device_id`.
