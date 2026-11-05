"""POST /investigate — runs one Alert Record (schema v3) through the investigation module."""
import json
import sys

import investigation as inv


def main():
    method, _, body = inv.parse_http(sys.stdin.buffer.read())
    if method != "POST":
        return inv.http_response(405, {"error": "Use POST with an Alert Record (schema_version 3) JSON body."})
    try:
        record = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return inv.http_response(400, {"error": f"Body is not valid JSON: {e}"})
    try:
        updated = inv.investigate(record)
    except inv.ContractError as e:
        cid = record.get("correlation_id") if isinstance(record, dict) else None
        print(json.dumps({"component": inv.COMPONENT, "correlation_id": cid, "event": "contract_error", "error": str(e)}), file=sys.stderr)
        return inv.http_response(400, {"error": f"Input does not match the Alert Record contract: {e}"})
    inv.http_response(200, updated)


if __name__ == "__main__":
    main()
