"""GET /test — runs the three sample records through the investigation module and shows the findings."""
import sys

import investigation as inv
from fixtures import all_fixtures


def main():
    sys.stdin.buffer.read()
    results = []
    for fx in all_fixtures():
        out = inv.investigate(fx["record"])["investigation"]
        results.append({
            "fixture": fx["name"],
            "expected_verdict": fx["expected_verdict"],
            "verdict": out["verdict"],
            "passed": out["verdict"] == fx["expected_verdict"],
            "risk_score": out["risk_score"],
            "confirmation_question": out["confirmation_question"],
            "findings": [{"check": f["check"], "severity": f["severity"], "finding": f["finding"]}
                         for f in out["findings"]],
            "investigation": out,
        })
    inv.http_response(200, {
        "code_version": inv.CODE_VERSION,
        "all_passed": all(r["passed"] for r in results),
        "results": results,
    })


if __name__ == "__main__":
    main()
