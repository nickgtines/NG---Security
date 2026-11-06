// Receives a Tines Case Action webhook, validates it, and maps the button label to an action key.

// Labels are matched case-insensitively after trimming. Add new case actions here.
const ACTIONS: Record<string, string> = {
  "contain host": "crowdstrike_contain_host",
  "kill process": "crowdstrike_kill_process",
  "revoke sessions": "okta_revoke_sessions",
  "suspend user": "okta_suspend_user",
  "force password reset": "okta_require_password_reset",
  "create slack channel": "slack_create_channel",
  "get user details": "okta_get_user_details",
  "ai summary": "ai_case_summary",
};

const raw = await Bun.stdin.text();
const sep = raw.indexOf("\r\n\r\n");
const bodyText = sep >= 0 ? raw.slice(sep + 4) : raw;

let payload: any;
try {
  payload = JSON.parse(bodyText);
} catch {
  console.error(JSON.stringify({ event: "invalid_json" }));
  process.exit(1);
}
// Accept either the raw Tines case-action body or a Tines event wrapper ({ body: {...} }).
if (payload?.body?.button && payload?.body?.case) payload = payload.body;

const { user, button, case: c } = payload ?? {};
if (!user || !button?.label || !c?.id) {
  console.error(JSON.stringify({ event: "missing_fields", has_user: !!user, has_button: !!button, has_case: !!c }));
  process.exit(1);
}

const label = String(button.label).trim();
const action = ACTIONS[label.toLowerCase()];
if (!action) {
  console.error(JSON.stringify({ event: "unsupported_label", label, case_id: c.id }));
  process.exit(1);
}

const userName = [user.first_name, user.last_name].filter(Boolean).join(" ") || user.email || `user ${user.id}`;

console.error(JSON.stringify({ event: "action_received", action, label, case_id: c.id, user: user.email }));
console.log(
  JSON.stringify({
    action,
    label,
    button_id: button.id,
    user: { id: user.id, name: userName, email: user.email ?? null },
    case: {
      id: c.id,
      name: c.name,
      url: c.url,
      team_id: c.team_id,
      metadata: c.metadata ?? {},
    },
  }),
);
