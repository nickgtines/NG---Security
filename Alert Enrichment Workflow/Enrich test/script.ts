// Emits the bundled sample alert record (with a fresh correlation_id) into Enrich.
// The enriched record comes back as this route's HTTP response.
import { randomUUID } from "node:crypto";
const rec = JSON.parse(await Bun.file("./sample-alert.json").text());
rec.correlation_id = randomUUID();
process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level: "info", step: "Enrich test", event: "sample_emitted", msg: "Sent sample alert to Enrich.", correlation_id: rec.correlation_id }) + "\n");
process.stdout.write(JSON.stringify(rec));
