import { handle } from "./respond.ts";
const raw = await Bun.stdin.text();
process.stdout.write(await handle(raw));
