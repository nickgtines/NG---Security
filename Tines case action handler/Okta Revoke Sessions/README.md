Clears all Okta sessions and OAuth tokens for the case user (`DELETE /api/v1/users/:id/sessions?oauthTokens=true`).

**Expected case action label:** `Revoke Sessions`

Runs only for action key `okta_revoke_sessions`. User from case metadata `email` or `username`.
