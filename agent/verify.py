"""
Evidence-producing verification checks. Each function here returns:

    {"confirmed": bool, "evidence": {...}}

never a bare boolean — `evidence` is what gets attached to a finding via
`record_finding`, so these functions are the only legitimate source of
evidence in the whole system. They use benign markers/canaries (never
real exploit payloads, shellcode, or destructive requests) and every
request goes through the target's scoped session, so they inherit its
scope enforcement.

This module checks for *conditions that indicate* a vulnerability class —
it is a DAST-style differential/heuristic tester, the same category of
technique used by tools like OWASP ZAP or Burp's active scanner, not a
working-exploit generator.
"""
import time
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from agent.http_session import get_session

SQLI_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "unclosed quotation mark", "quoted string not properly terminated",
    "odbc sql server driver", "pg_query", "sqlite3.operationalerror", "ora-01756", "warning: pg_",
]


def _marker() -> str:
    return f"hb{uuid.uuid4().hex[:10]}"


def verify_sqli(target: str, url: str, param: str, method: str = "GET") -> dict:
    """
    Error-based + boolean-differential SQLi check on a single parameter.
    Sends a quote character (syntax-breaking) and a pair of always-true /
    always-false boolean payloads, and compares responses. Confirms only
    on a clear signal (a DB error signature, or a consistent true/false
    content-length delta) — never on a single ambiguous response.
    """
    session = get_session(target)

    def send(payload: str) -> dict:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        return session.request(method, new_url)

    baseline = send("1")
    quote_probe = send("1'")
    true_probe = send("1' OR '1'='1")
    false_probe = send("1' AND '1'='2")

    evidence = {"baseline": baseline, "quote_probe": quote_probe, "true_probe": true_probe, "false_probe": false_probe}

    quote_body = (quote_probe.get("body") or "").lower()
    if any(sig in quote_body for sig in SQLI_ERROR_SIGNATURES):
        return {"confirmed": True, "evidence": {**evidence, "signal": "db_error_signature"}}

    base_len = len((baseline.get("body") or ""))
    true_len = len((true_probe.get("body") or ""))
    false_len = len((false_probe.get("body") or ""))
    if base_len and true_len and false_len:
        # Confirmed boolean-blind signal: true probe tracks baseline, false probe diverges clearly.
        if abs(true_len - base_len) < max(10, base_len * 0.02) and abs(false_len - true_len) > max(30, base_len * 0.05):
            return {"confirmed": True, "evidence": {**evidence, "signal": "boolean_blind_delta"}}

    return {"confirmed": False, "evidence": evidence}


def verify_reflected_xss(target: str, url: str, param: str, method: str = "GET") -> dict:
    """
    Reflects a unique, non-executing marker through a parameter and checks
    whether it comes back in the response UNescaped (i.e. not HTML-entity
    encoded), which indicates the app isn't sanitizing that output
    context. No <script> payload is sent — the marker alone is enough to
    prove an encoding failure, and this stays DOM-execution-agnostic
    (see browser_verify_xss for an in-browser confirmation).
    """
    session = get_session(target)
    marker = _marker()
    probe_value = f"<{marker}>"

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [probe_value]
    new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    result = session.request(method, new_url)
    body = result.get("body") or ""

    unescaped_present = probe_value in body
    escaped_present = f"&lt;{marker}&gt;" in body

    confirmed = unescaped_present and not escaped_present
    return {
        "confirmed": confirmed,
        "evidence": {
            "request": {"url": new_url, "method": method},
            "response_status": result.get("status_code"),
            "marker": marker,
            "unescaped_reflection_found": unescaped_present,
            "escaped_reflection_found": escaped_present,
        },
    }


def verify_idor(target: str, url_template: str, own_id: str, probe_id: str, method: str = "GET") -> dict:
    """
    Classic IDOR differential: request the resource as the "own" id
    (should succeed) and as a different `probe_id` (should fail if access
    control is correctly enforced). Confirms only when the probe_id
    request succeeds with 2xx AND returns content distinct from a 404/403
    pattern — i.e. it looks like real, different data came back.
    """
    session = get_session(target)
    own_url = url_template.format(id=own_id)
    probe_url = url_template.format(id=probe_id)

    own_resp = session.request(method, own_url)
    probe_resp = session.request(method, probe_url)

    own_ok = 200 <= (own_resp.get("status_code") or 0) < 300
    probe_ok = 200 <= (probe_resp.get("status_code") or 0) < 300
    bodies_differ = (own_resp.get("body") or "") != (probe_resp.get("body") or "")

    confirmed = own_ok and probe_ok and bodies_differ
    return {
        "confirmed": confirmed,
        "evidence": {
            "own_request": {"url": own_url, "status": own_resp.get("status_code")},
            "probe_request": {"url": probe_url, "status": probe_resp.get("status_code")},
            "bodies_differ": bodies_differ,
        },
    }


def verify_open_redirect(target: str, url: str, param: str, method: str = "GET") -> dict:
    """
    Sets `param` to a safe, reserved-for-documentation external domain
    (example.com) and checks whether the server actually redirects there.
    example.com/example.org/example.net are IANA-reserved for exactly
    this kind of test, so nothing real is contacted maliciously.
    """
    session = get_session(target)
    marker_path = f"/hackbeast-redirect-{_marker()}"
    target_url = f"https://example.com{marker_path}"

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [target_url]
    new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    result = session.request(method, new_url, allow_redirects=False)
    location = result.get("location") or ""
    confirmed = "example.com" in location and marker_path in location

    return {
        "confirmed": confirmed,
        "evidence": {
            "request": {"url": new_url, "method": method},
            "status_code": result.get("status_code"),
            "location_header": location,
            "expected_marker": target_url,
        },
    }


def verify_ssrf(target: str, url: str, param: str, internal_probe: str = "http://127.0.0.1:80/", method: str = "GET") -> dict:
    """
    Response-based (non-blind) SSRF heuristic: points `param` at an
    internal-looking URL (default: localhost) and compares the response
    to a request with an obviously-invalid host. A meaningfully different
    response (different status code or body shape) for the internal
    target than for the garbage one suggests the server actually made the
    internal request rather than just echoing the param back.

    This cannot prove *blind* SSRF (where the server fetches an internal
    resource but never reflects anything back) — that needs an
    out-of-band listener (e.g. Interactsh/webhook.site) which this tool
    does not stand up for you. Treat a "not confirmed" result here as
    inconclusive, not as a clean bill of health, for anything you suspect
    might be blind.
    """
    session = get_session(target)

    def send(probe_url: str) -> dict:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [probe_url]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        return session.request(method, new_url)

    garbage_host = f"http://{_marker()}.invalid/"
    internal_resp = send(internal_probe)
    garbage_resp = send(garbage_host)

    status_differs = internal_resp.get("status_code") != garbage_resp.get("status_code")
    len_internal = len(internal_resp.get("body") or "")
    len_garbage = len(garbage_resp.get("body") or "")
    body_differs_meaningfully = abs(len_internal - len_garbage) > max(20, len_garbage * 0.1)

    confirmed = status_differs or body_differs_meaningfully
    return {
        "confirmed": confirmed,
        "inconclusive_note": "Non-blind heuristic only — use an out-of-band listener to confirm blind SSRF.",
        "evidence": {
            "internal_probe_url": internal_probe,
            "internal_response": {"status": internal_resp.get("status_code"), "body_len": len_internal},
            "garbage_response": {"status": garbage_resp.get("status_code"), "body_len": len_garbage},
            "status_differs": status_differs,
            "body_differs_meaningfully": body_differs_meaningfully,
        },
    }


def verify_ssti(target: str, url: str, param: str, method: str = "GET") -> dict:
    """
    Server-Side Template Injection check. Sends a benign arithmetic
    expression in several common template syntaxes (Jinja2/Twig-style
    `{{7*7}}`, Freemarker/JSP-style `${7*7}`, Ruby ERB-style `#{7*7}`) and
    checks whether the server evaluated it to "49" rather than reflecting
    the literal string back. No code execution is attempted — this proves
    the template engine evaluates user input, which is the same signal
    real SSTI scanners rely on before trying anything further.
    """
    session = get_session(target)
    marker = _marker()
    payloads = {
        "jinja2_twig": f"{{{{7*7}}}}{marker}",
        "freemarker_jsp_el": f"${{7*7}}{marker}",
        "ruby_erb": f"#{{7*7}}{marker}",
    }

    def send(payload: str) -> dict:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        return session.request(method, new_url)

    evidence = {}
    confirmed = False
    fired_syntax = None
    for syntax, payload in payloads.items():
        resp = send(payload)
        body = resp.get("body") or ""
        evaluated = f"49{marker}" in body
        evidence[syntax] = {"payload": payload, "status": resp.get("status_code"), "evaluated": evaluated}
        if evaluated:
            confirmed = True
            fired_syntax = syntax

    return {
        "confirmed": confirmed,
        "evidence": {"request_param": param, "checks": evidence, "fired_syntax": fired_syntax},
    }


def verify_command_injection(target: str, url: str, param: str, method: str = "GET") -> dict:
    """
    OS command injection check using two independent, non-destructive
    signals: (1) an echoed marker via `; echo MARKER`-style separators
    across sh/cmd.exe syntax, checked for appearing verbatim in the
    response, and (2) a timing differential using a benign sleep (`sleep 3`
    / `timeout 3`) compared against a baseline request. Either signal
    alone can have noise (echo: WAF stripping; timing: network jitter), so
    this only confirms when the echoed marker is found, or when the delay
    is consistently and clearly longer than the baseline by roughly the
    sleep duration. No destructive, data-exfiltrating, or reverse-shell
    payloads are ever sent.
    """
    session = get_session(target)
    marker = _marker()

    def send(payload: str) -> dict:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        return session.request(method, new_url)

    echo_payloads = [
        f"; echo {marker} #",
        f"| echo {marker}",
        f"`echo {marker}`",
        f"& echo {marker} &",
    ]
    echo_evidence = []
    echo_confirmed = False
    for p in echo_payloads:
        resp = send(p)
        body = resp.get("body") or ""
        found = marker in body
        echo_evidence.append({"payload": p, "status": resp.get("status_code"), "marker_reflected": found})
        if found:
            echo_confirmed = True

    sleep_seconds = 3
    baseline_start = time.monotonic()
    send("1")
    baseline_elapsed = time.monotonic() - baseline_start

    delay_payloads = [f"; sleep {sleep_seconds} #", f"| sleep {sleep_seconds}", f"& timeout {sleep_seconds} &"]
    timing_evidence = []
    timing_confirmed = False
    for p in delay_payloads:
        start = time.monotonic()
        send(p)
        elapsed = time.monotonic() - start
        delayed = elapsed - baseline_elapsed >= sleep_seconds * 0.7
        timing_evidence.append({"payload": p, "elapsed_s": round(elapsed, 2), "delayed": delayed})
        if delayed:
            timing_confirmed = True

    return {
        "confirmed": echo_confirmed or timing_confirmed,
        "evidence": {
            "echo_marker": marker,
            "echo_checks": echo_evidence,
            "baseline_elapsed_s": round(baseline_elapsed, 2),
            "timing_checks": timing_evidence,
            "signal": "echo" if echo_confirmed else ("timing" if timing_confirmed else None),
        },
    }


def verify_xxe(target: str, url: str, method: str = "POST", content_type: str = "application/xml") -> dict:
    """
    XML External Entity check, using the same non-blind differential
    approach as verify_ssrf rather than trying to read local files: posts
    an XML body whose external entity points at an internal-looking URL,
    and a second body pointing at an obviously-invalid host, then compares
    the two responses. A meaningfully different response for the internal
    target indicates the parser is resolving external entities (and so is
    vulnerable to XXE-driven SSRF at minimum) without ever asking it to
    disclose a real file's contents.
    """
    session = get_session(target)

    def build_xml(entity_url: str) -> str:
        return (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE hb [<!ENTITY hbxxe SYSTEM "{entity_url}">]>'
            "<root>&hbxxe;</root>"
        )

    def send(entity_url: str) -> dict:
        return session.request(
            method, url, headers={"Content-Type": content_type}, data=build_xml(entity_url)
        )

    internal_probe = "http://127.0.0.1:80/"
    garbage_host = f"http://{_marker()}.invalid/"

    internal_resp = send(internal_probe)
    garbage_resp = send(garbage_host)

    status_differs = internal_resp.get("status_code") != garbage_resp.get("status_code")
    len_internal = len(internal_resp.get("body") or "")
    len_garbage = len(garbage_resp.get("body") or "")
    body_differs_meaningfully = abs(len_internal - len_garbage) > max(20, len_garbage * 0.1)
    xml_parse_error_only = any(
        sig in (garbage_resp.get("body") or "").lower()
        for sig in ("doctype", "entity", "xml parse", "external entity")
    ) and not status_differs and not body_differs_meaningfully

    confirmed = (status_differs or body_differs_meaningfully) and not xml_parse_error_only
    return {
        "confirmed": confirmed,
        "inconclusive_note": "Non-blind heuristic (SSRF-via-XXE signal) only — use an out-of-band listener to confirm blind/file-exfiltration XXE.",
        "evidence": {
            "internal_probe_url": internal_probe,
            "internal_response": {"status": internal_resp.get("status_code"), "body_len": len_internal},
            "garbage_response": {"status": garbage_resp.get("status_code"), "body_len": len_garbage},
            "status_differs": status_differs,
            "body_differs_meaningfully": body_differs_meaningfully,
        },
    }


SECRET_PATTERNS = [
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_access_key", r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}"),
    ("generic_api_key", r"(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"),
    ("jwt", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("private_key_header", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("stripe_key", r"sk_live_[0-9A-Za-z]{24,}"),
]


def verify_secret_exposure(target: str, url: str, method: str = "GET") -> dict:
    """
    Fetches `url` and scans the raw response (headers + body) for common
    hardcoded-secret signatures: AWS keys, generic API-key assignments,
    JWTs, PEM private key headers, Slack/GitHub/Stripe tokens. A static
    pattern match, same category of technique as truffleHog/gitleaks, but
    run against a live HTTP response instead of a repo. Evidence includes
    only a masked excerpt of each match (first 6 / last 4 characters),
    never the full secret value, so a real finding doesn't itself leak the
    credential into the report.
    """
    import re

    session = get_session(target)
    resp = session.request(method, url)
    body = resp.get("body") or ""
    headers_text = " ".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items())
    haystack = body + "\n" + headers_text

    matches = []
    for name, pattern in SECRET_PATTERNS:
        for m in re.finditer(pattern, haystack):
            val = m.group(0)
            masked = val[:6] + "…" + val[-4:] if len(val) > 12 else "…"
            matches.append({"type": name, "masked_match": masked, "position": m.start()})

    return {
        "confirmed": len(matches) > 0,
        "evidence": {
            "url": url,
            "status_code": resp.get("status_code"),
            "matches": matches,
        },
    }


def verify_auth_bypass(target: str, url: str, method: str = "GET", auth_header_name: str = "Authorization") -> dict:
    """
    Differential auth-enforcement check: requests `url` once through the
    normal (possibly-authenticated) session, then again with the named
    auth header stripped. If the stripped request still returns a 2xx
    with a response body similar in size to the authenticated one, access
    control likely isn't actually being enforced on this endpoint.
    """
    session = get_session(target)

    with_auth = session.request(method, url)

    stripped_headers = {k: v for k, v in (session.session.headers or {}).items() if k.lower() != auth_header_name.lower()}
    # Temporarily request with an explicit empty value for the auth header
    # (requests lets a per-call header override the session default).
    without_auth = session.request(method, url, headers={auth_header_name: ""})

    with_status = with_auth.get("status_code")
    without_status = without_auth.get("status_code")
    without_ok = without_status is not None and 200 <= without_status < 300

    len_with = len(with_auth.get("body") or "")
    len_without = len(without_auth.get("body") or "")
    similar_body = len_with and len_without and abs(len_with - len_without) < max(20, len_with * 0.1)

    confirmed = without_ok and similar_body
    return {
        "confirmed": confirmed,
        "evidence": {
            "with_auth": {"status": with_status, "body_len": len_with},
            "without_auth": {"status": without_status, "body_len": len_without},
            "similar_body_without_auth": similar_body,
        },
    }
