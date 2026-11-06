Webhook trigger (`/case-actions`, external ID auth) for Tines case actions. Parses the case-action body (or a Tines event wrapper with `body`), validates `user`, `button`, and `case`, and maps `button.label` to an action key.

Accepted labels (case-insensitive): `Contain Host`, `Kill Process`, `Revoke Sessions`, `Suspend User`, `Force Password Reset`, `Create Slack Channel`, `Get User Details`. Any other label fails the run and the case is not changed. Edit `ACTIONS` in `script.ts` to add labels.
