Read-only lookup of the case user in Okta (`GET /api/v1/users/:login`), returning profile, status, and key timestamps. Makes no changes in Okta.

**Expected case action label:** `Get User Details`

Runs only for action key `okta_get_user_details`. User from case metadata `email` or `username`.
