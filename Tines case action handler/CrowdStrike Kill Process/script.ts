// MOCKED CrowdStrike Falcon action: kill a process via Real Time Response. No real API call is made.
const ctx = JSON.parse(await Bun.stdin.text());
if (ctx.action !== "crowdstrike_kill_process") process.exit(0); // Not this step's action: emit nothing.

const md = ctx.case.metadata ?? {};
const host = md.hostname ?? md.host ?? md.device_id ?? "UNKNOWN-HOST";
const proc = md.process_name ?? md.process_id ?? md.sha256 ?? "UNKNOWN-PROCESS";
const target = `${proc} on ${host}`;
// Shape mirrors POST /real-time-response/entities/active-responder-command/v1 (base_command: kill)
const response = {
  meta: { query_time: 0.48, powered_by: "empower-api", trace_id: crypto.randomUUID() },
  resources: [{ session_id: crypto.randomUUID(), cloud_request_id: crypto.randomUUID(), base_command: "kill", command_string: `kill ${proc}`, hostname: host, complete: true, stdout: `Process ${proc} terminated`, stderr: "" }],
  errors: [],
};
console.error(JSON.stringify({ event: "crowdstrike_mock", action: ctx.action, target, case_id: ctx.case.id }));
console.log(JSON.stringify({ context: ctx, result: { system: "CrowdStrike Falcon (mocked)", target, success: true, response } }));
