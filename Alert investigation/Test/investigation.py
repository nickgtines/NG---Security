"""
Alert Investigation — deterministic investigation logic (replaces the Jupyter notebook).

Contract: Alert Record schema_version "3". This module reads `alert` and `enrichment`,
fills in ONLY `investigation`, and appends exactly one entry to `trace`.

Pure and deterministic: no network, no clock reads for decisions, no randomness, no AI.
All "time" comparisons are made relative to timestamps inside the record itself.
Every log line is single-line JSON on stderr and includes correlation_id, so a run's
logs read like notebook cells: one "cell" per function with its input summary and output.
"""

import copy
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CODE_VERSION = "alert-investigation/1.0.0"
COMPONENT = "Alert Investigation"

# Okta groups whose members are treated as privileged (raises other findings one level).
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Global Administrators",
    "Okta Super Admins",
    "AWS-Admins",
    "Security-Admins",
    "IT-Admins",
]

IMPOSSIBLE_TRAVEL_WINDOW = timedelta(hours=2)
STALE_HOST_AFTER = timedelta(days=7)

# Client apps that indicate legacy (basic) authentication in Entra/Sentinel sign-in logs.
LEGACY_AUTH_CLIENTS = {
    "exchange activesync", "imap", "imap4", "pop", "pop3", "smtp", "authenticated smtp",
    "other clients", "exchange web services", "mapi over http", "offline address book",
    "autodiscover", "exchange online powershell", "outlook anywhere (rpc over http)",
}

# Living-off-the-land binary patterns (name, compiled regex over the command line).
LOLBIN_PATTERNS = [
    ("encoded PowerShell", re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\s[-/]e(nc(odedcommand)?|c)?\s+[A-Za-z0-9+/=]{8,}", re.I)),
    ("certutil -urlcache", re.compile(r"\bcertutil(\.exe)?\b.*[-/]urlcache", re.I)),
    ("rundll32 with a URL", re.compile(r"\brundll32(\.exe)?\b.*(https?://|\\\\[^\\]+\\)", re.I)),
    ("mshta http", re.compile(r"\bmshta(\.exe)?\b.*https?://", re.I)),
]

SEVERITY_ORDER = ["info", "low", "medium", "high"]
# Weights used by decide_verdict.
SEVERITY_WEIGHTS = {"info": 0, "low": 10, "medium": 25, "high": 40}


class ContractError(ValueError):
    """Raised when the input does not match the Alert Record contract (→ HTTP 400)."""


# ---------------------------------------------------------------------------
# Logging — notebook-style "cells"
# ---------------------------------------------------------------------------
_CORRELATION_ID = None


def log(event, **fields):
    line = {"component": COMPONENT, "correlation_id": _CORRELATION_ID, "event": event}
    line.update(fields)
    print(json.dumps(line, default=str, sort_keys=True), file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_ts(value):
    """Parse an ISO 8601 timestamp to an aware UTC datetime, or None."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip().replace("Z", "+00:00")
    # Trim fractional seconds beyond microseconds (Sentinel emits 7 digits).
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_utc(dt):
    return dt.strftime("%Y-%m-%d %H:%M")


def fmt_friendly(dt):
    """e.g. 'Wednesday, November 4, 2026 at 14:22 UTC'."""
    return f"{dt.strftime('%A, %B')} {dt.day}, {dt.year} at {dt.strftime('%H:%M')} UTC"


# ISO 3166-1 alpha-2 → English short name, for human-readable questions.
COUNTRY_NAMES = dict(x.split("=") for x in (
    "AD=Andorra|AE=the United Arab Emirates|AF=Afghanistan|AG=Antigua and Barbuda|AL=Albania|AM=Armenia|"
    "AO=Angola|AR=Argentina|AT=Austria|AU=Australia|AZ=Azerbaijan|BA=Bosnia and Herzegovina|BB=Barbados|"
    "BD=Bangladesh|BE=Belgium|BF=Burkina Faso|BG=Bulgaria|BH=Bahrain|BI=Burundi|BJ=Benin|BN=Brunei|"
    "BO=Bolivia|BR=Brazil|BS=the Bahamas|BT=Bhutan|BW=Botswana|BY=Belarus|BZ=Belize|CA=Canada|"
    "CD=the Democratic Republic of the Congo|CF=the Central African Republic|CG=the Republic of the Congo|"
    "CH=Switzerland|CI=Côte d'Ivoire|CL=Chile|CM=Cameroon|CN=China|CO=Colombia|CR=Costa Rica|CU=Cuba|"
    "CV=Cape Verde|CY=Cyprus|CZ=the Czech Republic|DE=Germany|DJ=Djibouti|DK=Denmark|DM=Dominica|"
    "DO=the Dominican Republic|DZ=Algeria|EC=Ecuador|EE=Estonia|EG=Egypt|ER=Eritrea|ES=Spain|ET=Ethiopia|"
    "FI=Finland|FJ=Fiji|FR=France|GA=Gabon|GB=the United Kingdom|GD=Grenada|GE=Georgia|GH=Ghana|"
    "GM=the Gambia|GN=Guinea|GQ=Equatorial Guinea|GR=Greece|GT=Guatemala|GW=Guinea-Bissau|GY=Guyana|"
    "HK=Hong Kong|HN=Honduras|HR=Croatia|HT=Haiti|HU=Hungary|ID=Indonesia|IE=Ireland|IL=Israel|IN=India|"
    "IQ=Iraq|IR=Iran|IS=Iceland|IT=Italy|JM=Jamaica|JO=Jordan|JP=Japan|KE=Kenya|KG=Kyrgyzstan|KH=Cambodia|"
    "KM=Comoros|KN=Saint Kitts and Nevis|KP=North Korea|KR=South Korea|KW=Kuwait|KZ=Kazakhstan|LA=Laos|"
    "LB=Lebanon|LC=Saint Lucia|LI=Liechtenstein|LK=Sri Lanka|LR=Liberia|LS=Lesotho|LT=Lithuania|"
    "LU=Luxembourg|LV=Latvia|LY=Libya|MA=Morocco|MC=Monaco|MD=Moldova|ME=Montenegro|MG=Madagascar|"
    "MK=North Macedonia|ML=Mali|MM=Myanmar|MN=Mongolia|MO=Macau|MR=Mauritania|MT=Malta|MU=Mauritius|"
    "MV=the Maldives|MW=Malawi|MX=Mexico|MY=Malaysia|MZ=Mozambique|NA=Namibia|NE=Niger|NG=Nigeria|"
    "NI=Nicaragua|NL=the Netherlands|NO=Norway|NP=Nepal|NZ=New Zealand|OM=Oman|PA=Panama|PE=Peru|"
    "PG=Papua New Guinea|PH=the Philippines|PK=Pakistan|PL=Poland|PR=Puerto Rico|PS=Palestine|PT=Portugal|"
    "PY=Paraguay|QA=Qatar|RO=Romania|RS=Serbia|RU=Russia|RW=Rwanda|SA=Saudi Arabia|SB=the Solomon Islands|"
    "SC=Seychelles|SD=Sudan|SE=Sweden|SG=Singapore|SI=Slovenia|SK=Slovakia|SL=Sierra Leone|SM=San Marino|"
    "SN=Senegal|SO=Somalia|SR=Suriname|SS=South Sudan|SV=El Salvador|SY=Syria|SZ=Eswatini|TD=Chad|TG=Togo|"
    "TH=Thailand|TJ=Tajikistan|TL=Timor-Leste|TM=Turkmenistan|TN=Tunisia|TR=Turkey|TT=Trinidad and Tobago|"
    "TW=Taiwan|TZ=Tanzania|UA=Ukraine|UG=Uganda|US=the United States|UY=Uruguay|UZ=Uzbekistan|"
    "VE=Venezuela|VN=Vietnam|YE=Yemen|ZA=South Africa|ZM=Zambia|ZW=Zimbabwe"
).split("|"))


def country_name(value):
    """Spell out a 2-letter country code; pass through anything else (already a name)."""
    s = str(value).strip()
    return COUNTRY_NAMES.get(s.upper(), s) if len(s) == 2 else s


# Identity provider each alert source's sign-in evidence comes from.
SIGNIN_PROVIDER_BY_SOURCE = {"sentinel": "Microsoft Entra ID"}


def finding(check, severity, text, evidence):
    return {"check": check, "severity": severity, "finding": text, "evidence": evidence}


def _first(d, *keys):
    """First non-empty value among several possible field names (source formats vary)."""
    for k in keys:
        cur = d
        for part in k.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur not in (None, ""):
            return cur
    return None


def enrichment_of(record):
    return record.get("enrichment") or {}


def alert_signins(record):
    """Normalise alert.evidence sign-ins to {time, country, ip, success, client_app, source}."""
    out = []
    for ev in record["alert"].get("evidence") or []:
        if not isinstance(ev, dict) or ev.get("type") != "signin":
            continue
        d = ev.get("details") or {}
        result = _first(d, "result", "status", "resultType", "status.errorCode")
        if isinstance(result, str):
            success = result.lower() in ("success", "succeeded", "0")
        elif isinstance(result, (int, float)) and not isinstance(result, bool):
            success = result == 0
        elif isinstance(d.get("success"), bool):
            success = d["success"]
        else:
            success = None
        out.append({
            "time": parse_ts(ev.get("timestamp")),
            "timestamp": ev.get("timestamp"),
            "country": _first(d, "country", "location.countryOrRegion", "countryOrRegion"),
            "ip": _first(d, "ip", "ipAddress", "source_ip"),
            "success": success,
            "client_app": _first(d, "client_app", "clientAppUsed", "client"),
            "legacy_auth": d.get("legacy_auth") is True,
            "provider": _first(d, "provider", "identity_provider", "idp")
                        or SIGNIN_PROVIDER_BY_SOURCE.get(record["alert"].get("source")),
            "app": _first(d, "app", "application", "app_name", "appDisplayName",
                          "resourceDisplayName", "target_app"),
            "source": "alert.evidence",
        })
    return out


def okta_logins(record):
    uc = enrichment_of(record).get("user_context") or {}
    out = []
    for l in uc.get("recent_logins") or []:
        if isinstance(l, dict):
            out.append({"time": parse_ts(l.get("time")), "timestamp": l.get("time"),
                        "country": l.get("country"), "ip": l.get("ip"),
                        "provider": "Okta" if str(uc.get("provider") or "okta").lower() == "okta" else uc.get("provider"),
                        "app": l.get("app") or l.get("application"),
                        "source": "user_context.recent_logins"})
    return out


def _public(s):
    """Sign-in dict without internal datetime, for evidence output."""
    return {k: v for k, v in s.items() if k != "time"}


# ---------------------------------------------------------------------------
# Checks — each takes the record and returns a finding dict or None
# ---------------------------------------------------------------------------
def check_ioc_reputation(record):
    """Any malicious IOC result → high; else any suspicious → medium.
    Evidence is the matching enrichment.ioc_results entries."""
    results = enrichment_of(record).get("ioc_results") or []
    malicious = [r for r in results if isinstance(r, dict) and r.get("verdict") == "malicious"]
    suspicious = [r for r in results if isinstance(r, dict) and r.get("verdict") == "suspicious"]
    if malicious:
        iocs = sorted({str(r.get("ioc")) for r in malicious})
        return finding("check_ioc_reputation", "high",
                       f"{len(malicious)} malicious IOC result(s): {', '.join(iocs)}", malicious)
    if suspicious:
        iocs = sorted({str(r.get("ioc")) for r in suspicious})
        return finding("check_ioc_reputation", "medium",
                       f"{len(suspicious)} suspicious IOC result(s): {', '.join(iocs)}", suspicious)
    return None


def check_impossible_travel(record):
    """Sign-ins from 2+ different countries within 2 hours of each other, using
    alert.evidence sign-ins plus enrichment.user_context.recent_logins.
    Severity medium. The evidence lists the conflicting pair(s)."""
    signins = [s for s in alert_signins(record) + okta_logins(record)
               if s["time"] and s.get("country")]
    # Stable sort: time, then source, then country — deterministic pairing.
    signins.sort(key=lambda s: (s["time"], s["source"], str(s["country"])))
    pairs = []
    for i, a in enumerate(signins):
        for b in signins[i + 1:]:
            if b["time"] - a["time"] > IMPOSSIBLE_TRAVEL_WINDOW:
                break
            if str(a["country"]).upper() != str(b["country"]).upper():
                pairs.append([_public(a), _public(b)])
    if not pairs:
        return None
    first, second = pairs[0]
    return finding("check_impossible_travel", "medium",
                   f"Sign-ins from {first['country']} and {second['country']} within 2 hours "
                   f"({len(pairs)} conflicting pair(s))",
                   pairs)


def check_signin_risk(record):
    """Medium if any of: failed sign-ins followed by a success, a legacy-auth sign-in,
    or a sign-in from a country not seen in user_context.recent_logins."""
    signins = sorted((s for s in alert_signins(record)),
                     key=lambda s: (s["time"] or datetime.min.replace(tzinfo=timezone.utc)))
    reasons, evidence = [], []

    # 1. One or more failures followed by a success.
    failures = []
    for s in signins:
        if s["success"] is False:
            failures.append(s)
        elif s["success"] is True and failures:
            reasons.append(f"{len(failures)} failed sign-in(s) followed by a success")
            evidence.append({"reason": "failures_then_success",
                             "signins": [_public(x) for x in failures + [s]]})
            break

    # 2. Legacy authentication.
    legacy = [s for s in signins
              if s["legacy_auth"] or str(s.get("client_app") or "").lower() in LEGACY_AUTH_CLIENTS]
    if legacy:
        reasons.append(f"legacy authentication ({legacy[0]['client_app'] or 'flagged'})")
        evidence.append({"reason": "legacy_auth", "signins": [_public(x) for x in legacy]})

    # 3. Country not in the user's recent Okta logins (only when we have a baseline).
    known = {str(l["country"]).upper() for l in okta_logins(record) if l.get("country")}
    if known:
        new = [s for s in signins if s.get("country") and str(s["country"]).upper() not in known]
        if new:
            reasons.append("sign-in from new country " + ", ".join(sorted({str(s['country']) for s in new})))
            evidence.append({"reason": "new_country", "known_countries": sorted(known),
                             "signins": [_public(x) for x in new]})

    if not reasons:
        return None
    return finding("check_signin_risk", "medium", "Risky sign-in: " + "; ".join(reasons), evidence)


def check_suspicious_process(record):
    """Process evidence whose command line matches a LOLBin pattern → high."""
    matches = []
    for ev in record["alert"].get("evidence") or []:
        if not isinstance(ev, dict) or ev.get("type") != "process":
            continue
        d = ev.get("details") or {}
        cmd = _first(d, "command_line", "CommandLine", "cmdline", "commandLine") or ""
        for name, pattern in LOLBIN_PATTERNS:
            if isinstance(cmd, str) and pattern.search(cmd):
                matches.append({"pattern": name, "timestamp": ev.get("timestamp"), "details": d})
                break
    if not matches:
        return None
    names = sorted({m["pattern"] for m in matches})
    return finding("check_suspicious_process", "high",
                   f"LOLBin execution detected: {', '.join(names)}", matches)


def check_privileged_user(record):
    """User is in an Okta group listed in PRIVILEGED_GROUPS → info finding.
    apply_privilege_uplift() then raises every other finding by one severity level."""
    uc = enrichment_of(record).get("user_context") or {}
    priv = {g.lower() for g in PRIVILEGED_GROUPS}
    hits = sorted(g for g in (uc.get("groups") or []) if isinstance(g, str) and g.lower() in priv)
    if not hits:
        return None
    upn = (record["alert"].get("user") or {}).get("upn")
    return finding("check_privileged_user", "info",
                   f"User {upn} is privileged (groups: {', '.join(hits)}); other findings raised one level",
                   hits)


def check_host_posture(record):
    """CrowdStrike host not found, or last_seen more than 7 days before the alert's
    last_seen → low ("unmanaged or stale host"). Skipped if host context is absent or errored."""
    hc = enrichment_of(record).get("host_context")
    if not isinstance(hc, dict) or hc.get("error"):
        return None
    hostname = (record["alert"].get("host") or {}).get("hostname")
    if hc.get("found") is False:
        return finding("check_host_posture", "low",
                       f"Unmanaged or stale host: {hostname} not found in CrowdStrike", [hc])
    host_seen = parse_ts(hc.get("last_seen"))
    reference = parse_ts(record["alert"].get("last_seen"))
    if host_seen and reference and reference - host_seen > STALE_HOST_AFTER:
        days = (reference - host_seen).days
        return finding("check_host_posture", "low",
                       f"Unmanaged or stale host: {hostname} last seen by CrowdStrike {days} days before the alert",
                       [hc])
    return None


# ---------------------------------------------------------------------------
# HOOK: external findings
# ---------------------------------------------------------------------------
def external_findings(record):
    """### HOOK — external_findings ###
    Reserved for internal dispatch (findings produced by other internal components).
    Must return a list of finding dicts; these feed decide_verdict. Returns [] for now."""
    return []


# ---------------------------------------------------------------------------
# Severity uplift and verdict
# ---------------------------------------------------------------------------
def apply_privilege_uplift(findings):
    """If check_privileged_user fired, raise every other non-info finding one level (max high)."""
    if not any(f["check"] == "check_privileged_user" for f in findings):
        return findings
    out = []
    for f in findings:
        f = dict(f)
        if f["check"] != "check_privileged_user" and f["severity"] in ("low", "medium"):
            f["original_severity"] = f["severity"]
            f["severity"] = SEVERITY_ORDER[SEVERITY_ORDER.index(f["severity"]) + 1]
        out.append(f)
    return out


def decide_verdict(findings):
    """Return (verdict, risk_score, confirmation_question)."""
    # Rule 1: risk_score = sum of weights (info 0, low 10, medium 25, high 40), capped at 100.
    risk_score = min(100, sum(SEVERITY_WEIGHTS.get(f.get("severity"), 0) for f in findings))

    # Rule 2: any high finding → escalate.
    if any(f.get("severity") == "high" for f in findings):
        return "escalate", risk_score, None

    # Rule 3: else, if check_impossible_travel or check_signin_risk fired →
    #         needs_user_confirmation, asking "Did you sign in from <country> at <time UTC>?"
    #         using the most recent unusual alert sign-in.
    fired = {f["check"]: f for f in findings}
    if "check_impossible_travel" in fired or "check_signin_risk" in fired:
        candidates = []
        if "check_impossible_travel" in fired:
            for pair in fired["check_impossible_travel"]["evidence"]:
                candidates.extend(pair)
        if "check_signin_risk" in fired:
            for ev in fired["check_signin_risk"]["evidence"]:
                candidates.extend(ev.get("signins", []))
        dated = [c for c in candidates if c.get("country") and parse_ts(c.get("timestamp"))]
        alert_side = [c for c in dated if c.get("source") == "alert.evidence"] or dated
        if alert_side:
            pick = max(alert_side, key=lambda c: (parse_ts(c["timestamp"]), str(c["country"])))
            provider, app = pick.get("provider"), pick.get("app")
            if provider and app and str(app).lower() != str(provider).lower():
                target = f" to {app} (via {provider})"
            elif provider or app:
                target = f" to {provider or app}"
            else:
                target = ""
            question = (f"Did you sign in{target} from {country_name(pick['country'])} "
                        f"on {fmt_friendly(parse_ts(pick['timestamp']))}?")
        else:
            question = "Did you recently sign in from an unfamiliar location?"
        return "needs_user_confirmation", risk_score, question

    # Rule 4: else → benign.
    return "benign", risk_score, None


# ---------------------------------------------------------------------------
# Contract validation
# ---------------------------------------------------------------------------
def _req(cond, msg):
    if not cond:
        raise ContractError(msg)


def validate(record):
    _req(isinstance(record, dict), "body must be a JSON object")
    _req(record.get("schema_version") == "3", 'schema_version must be "3"')
    _req(isinstance(record.get("correlation_id"), str) and record["correlation_id"], "correlation_id must be a non-empty string")
    a = record.get("alert")
    _req(isinstance(a, dict), "alert must be an object")
    for k in ("id", "rule_name", "title"):
        _req(isinstance(a.get(k), str), f"alert.{k} must be a string")
    _req(a.get("source") in ("sentinel", "crowdstrike"), "alert.source must be sentinel or crowdstrike")
    _req(a.get("severity") in ("informational", "low", "medium", "high", "critical"), "alert.severity is invalid")
    for k in ("first_seen", "last_seen"):
        _req(parse_ts(a.get(k)) is not None, f"alert.{k} must be an ISO 8601 timestamp")
    _req(isinstance(a.get("user", {}), dict) and isinstance(a.get("host", {}), dict), "alert.user and alert.host must be objects")
    ev = a.get("evidence", [])
    _req(isinstance(ev, list) and all(isinstance(e, dict) for e in ev), "alert.evidence must be an array of objects")
    for i, e in enumerate(ev):
        _req(e.get("type") in ("signin", "process", "file", "url", "ip", "other"), f"alert.evidence[{i}].type is invalid")
        _req(isinstance(e.get("details", {}), dict), f"alert.evidence[{i}].details must be an object")
    en = record.get("enrichment")
    _req(en is None or isinstance(en, dict), "enrichment must be an object or null")
    if isinstance(en, dict):
        _req(isinstance(en.get("ioc_results", []), list), "enrichment.ioc_results must be an array")
        _req(en.get("user_context") is None or isinstance(en["user_context"], dict), "enrichment.user_context must be an object or null")
        if isinstance(en.get("user_context"), dict):
            uc = en["user_context"]
            _req(isinstance(uc.get("groups", []), list), "enrichment.user_context.groups must be an array")
            _req(isinstance(uc.get("recent_logins", []), list), "enrichment.user_context.recent_logins must be an array")
        _req(en.get("host_context") is None or isinstance(en["host_context"], dict), "enrichment.host_context must be an object or null")
    _req(isinstance(record.get("trace"), list), "trace must be an array")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
CHECKS = [
    check_ioc_reputation,
    check_impossible_travel,
    check_signin_risk,
    check_suspicious_process,
    check_privileged_user,
    check_host_posture,
]


def input_summary(record):
    a, en = record["alert"], enrichment_of(record)
    uc, hc = en.get("user_context") or {}, en.get("host_context") or {}
    return {
        "alert_id": a.get("id"), "rule_name": a.get("rule_name"),
        "upn": (a.get("user") or {}).get("upn"), "hostname": (a.get("host") or {}).get("hostname"),
        "evidence_types": sorted({e.get("type") for e in a.get("evidence") or []}),
        "ioc_results": len(en.get("ioc_results") or []), "ioc_summary": en.get("ioc_summary"),
        "okta_groups": uc.get("groups"), "recent_login_countries": sorted({str(l.get("country")) for l in uc.get("recent_logins") or []}),
        "host_found": hc.get("found"), "host_last_seen": hc.get("last_seen"),
    }


def run_url():
    for k in ("_3B_RUN_URL", "_3B_EXECUTION_URL"):
        if os.environ.get(k):
            return os.environ[k]
    return None


def investigate(record):
    """Validate (raises ContractError), run every check, decide, and return the updated record.
    Never raises for a valid record: errors are captured in findings and the trace entry."""
    global _CORRELATION_ID
    validate(record)
    started = time.monotonic()
    record = copy.deepcopy(record)
    _CORRELATION_ID = record["correlation_id"]
    log("cell:input", code_version=CODE_VERSION, summary=input_summary(record))

    findings, errors = [], []
    for fn in CHECKS + [external_findings]:
        try:
            result = fn(record)
            log(f"cell:{fn.__name__}", output=result)
            if fn is external_findings:
                findings.extend(result or [])
            elif result is not None:
                findings.append(result)
        except Exception as e:  # keep going; record the error
            msg = f"{fn.__name__}: {type(e).__name__}: {e}"
            errors.append(msg)
            log(f"cell:{fn.__name__}", error=msg)
            findings.append(finding(fn.__name__, "info", f"Check failed: {type(e).__name__}: {e}", []))

    error_text = "; ".join(errors) or None
    try:
        findings = apply_privilege_uplift(findings)
        verdict, risk, question = decide_verdict(findings)
        log("cell:decide_verdict", verdict=verdict, risk_score=risk, confirmation_question=question,
            severities=[(f["check"], f["severity"]) for f in findings])
    except Exception as e:
        # Fail safe: if the verdict cannot be computed, escalate for a human to look.
        error_text = "; ".join(filter(None, [error_text, f"decide_verdict: {type(e).__name__}: {e}"]))
        verdict, risk, question = "escalate", 100, None
        log("cell:decide_verdict", error=error_text)

    record["investigation"] = {
        "verdict": verdict,
        "risk_score": risk,
        "findings": findings,
        "confirmation_question": question,
        "code_version": CODE_VERSION,
    }
    fired = [f["check"] for f in findings]
    record["trace"].append({
        "component": COMPONENT,
        "decision": verdict,
        "reason": f"risk_score {risk}; findings: {', '.join(fired) if fired else 'none'}",
        "duration_ms": int((time.monotonic() - started) * 1000),
        "run_url": run_url(),
        "error": error_text,
    })
    log("cell:output", verdict=verdict, risk_score=risk, findings=len(findings), error=error_text)
    return record


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def http_response(status, obj):
    reason = {200: "OK", 400: "Bad Request", 405: "Method Not Allowed"}.get(status, "OK")
    body = json.dumps(obj, indent=2, default=str).encode()
    head = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode()
    sys.stdout.buffer.write(head + body)
    sys.stdout.buffer.flush()


def parse_http(raw):
    """Return (method, path, body_bytes). Accepts a raw JSON body from a linked step too."""
    if raw.lstrip().startswith(b"{"):
        return "POST", "", raw
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    method, path = (parts[0], parts[1]) if len(parts) > 1 else ("", "")
    headers = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    if "chunked" in headers.get("transfer-encoding", "").lower():
        out, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out, rest = out + rest[:size], rest[size + 2:]
        body = out
    return method.upper(), path, body
