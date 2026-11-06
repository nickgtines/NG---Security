// MOCKED CrowdStrike Falcon action: network-contain a host. No real API call is made.
const ctx = JSON.parse(await Bun.stdin.text());
if (ctx.action !== "crowdstrike_contain_host") process.exit(0); // Not this step's action: emit nothing.

const md = ctx.case.metadata ?? {};
const target = md.hostname ?? md.host ?? md.device_id ?? "UNKNOWN-HOST";
const deviceId = md.device_id ?? crypto.randomUUID().replace(/-/g, "");
// Shape mirrors POST /devices/entities/devices-actions/v2?action_name=contain
const response = {
  meta: { query_time: 0.21, powered_by: "device-api", trace_id: crypto.randomUUID() },
  resources: [{ id: deviceId, hostname: target, path: "/devices/entities/devices-actions/v2", action_name: "contain", status: "containment_pending" }],
  errors: [],
};
console.error(JSON.stringify({ event: "crowdstrike_mock", action: ctx.action, target, case_id: ctx.case.id }));
console.log(JSON.stringify({ context: ctx, result: { system: "CrowdStrike Falcon (mocked)", target, success: true, response } }));
