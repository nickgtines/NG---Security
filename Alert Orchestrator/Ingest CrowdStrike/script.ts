import { ingest, normalize_crowdstrike } from "./alert";
await ingest("crowdstrike", normalize_crowdstrike);
