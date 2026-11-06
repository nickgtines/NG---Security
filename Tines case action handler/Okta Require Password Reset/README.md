Expires the case user's Okta password so they must reset it at next sign-in (`POST /api/v1/users/:id/lifecycle/expire_password`).

**Expected case action label:** `Force Password Reset`

Runs only for action key `okta_require_password_reset`. User from case metadata `email` or `username`.
