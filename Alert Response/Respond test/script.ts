import { handle } from "./respond.ts";
import sample from "./sample.json";
// GET (or empty POST) runs the bundled sample record; POST with a body runs that record.
const raw = await Bun.stdin.text();
process.stdout.write(await handle(raw, sample));
