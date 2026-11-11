"""
Playwright-driven browser checks — closes the biggest gap against
Strix-style agents, which rely on real browser automation rather than raw
HTTP requests for anything JS-rendered: reflected XSS that only fires
after client-side rendering, CSRF token presence, clickjacking headers,
and a single-credential login flow test.

Every function here scope-checks the target host before navigating, same
as agent/http_session.py, and none of them brute-force credentials —
browser_login_flow_test takes exactly one username/password pair the
caller supplies, never a list to iterate.

Requires the `playwright` Python package AND its browser binaries
(`playwright install chromium`). If either is missing, functions return
a clear {"error": ...} instead of raising, so a missing browser doesn't
crash the whole agent run — it just means this tool is unavailable.
"""
import uuid
from urllib.parse import urlparse

from agent.scope import is_authorized


class BrowserUnavailable(RuntimeError):
    pass


def _check_host(url: str) -> None:
    host = urlparse(url).hostname or ""
    if not is_authorized(host):
        raise PermissionError(f"Host '{host}' from URL '{url}' is not in scope.txt — refusing to open it.")


def _get_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise BrowserUnavailable(
            "playwright is not installed. Run: pip install playwright && playwright install chromium"
        ) from e
    return sync_playwright


def browser_verify_xss(url: str, param: str = None, timeout_ms: int = 10000) -> dict:
    """
    Loads `url` (optionally with a unique marker injected into `param`)
    in a real headless browser and checks whether a JS alert/dialog fires
    or whether the marker ends up as a live DOM element rather than
    escaped text — i.e. confirms DOM execution, not just an unescaped
    string in the raw HTTP response (that's verify_reflected_xss).
    """
    _check_host(url)
    try:
        sync_playwright = _get_playwright()
    except BrowserUnavailable as e:
        return {"confirmed": False, "evidence": {"error": str(e)}}

    marker = f"hbxss{uuid.uuid4().hex[:8]}"
    test_url = url
    if param:
        sep = "&" if "?" in url else "?"
        probe = f"<img src=x onerror=\"window.__hb_xss_fired='{marker}'\">"
        test_url = f"{url}{sep}{param}={probe}"

    dialog_fired = {"value": False}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("dialog", lambda d: (dialog_fired.__setitem__("value", True), d.dismiss()))
        try:
            page.goto(test_url, timeout=timeout_ms, wait_until="load")
            page.wait_for_timeout(500)
            js_flag = page.evaluate("() => window.__hb_xss_fired || null")
        except Exception as e:
            browser.close()
            return {"confirmed": False, "evidence": {"error": str(e), "url": test_url}}
        browser.close()

    confirmed = dialog_fired["value"] or js_flag == marker
    return {
        "confirmed": confirmed,
        "evidence": {
            "url": test_url,
            "marker": marker,
            "dialog_fired": dialog_fired["value"],
            "js_marker_set": js_flag == marker,
        },
    }


def browser_check_clickjacking(url: str, timeout_ms: int = 10000) -> dict:
    """
    Checks X-Frame-Options and Content-Security-Policy's frame-ancestors
    directive on `url`. Absence of both means the page can likely be
    embedded in an attacker's <iframe>, enabling clickjacking. This is a
    header check (fast, reliable) rather than an actual iframe-embed
    attempt, which adds little certainty over the header check itself.
    """
    _check_host(url)
    try:
        sync_playwright = _get_playwright()
    except BrowserUnavailable as e:
        return {"confirmed": False, "evidence": {"error": str(e)}}

    headers = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            resp = page.goto(url, timeout=timeout_ms, wait_until="load")
            headers = resp.headers if resp else {}
        except Exception as e:
            browser.close()
            return {"confirmed": False, "evidence": {"error": str(e)}}
        browser.close()

    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    has_protection = bool(xfo) or "frame-ancestors" in csp.lower()

    return {
        "confirmed": not has_protection,
        "evidence": {
            "url": url,
            "x_frame_options": xfo or None,
            "csp_frame_ancestors_present": "frame-ancestors" in csp.lower(),
            "csp_header": csp or None,
        },
    }


def browser_check_csrf_protection(url: str, form_selector: str = "form", timeout_ms: int = 10000) -> dict:
    """
    Loads `url`, finds the first matching form, and checks for a hidden
    input whose name/id suggests a CSRF token (csrf, xsrf, authenticity,
    _token, etc.), plus whether cookies are set with SameSite=Strict/Lax.
    Absence of both is a real weakness, though some apps use header-based
    tokens (e.g. custom AJAX headers) this check won't see.
    """
    _check_host(url)
    try:
        sync_playwright = _get_playwright()
    except BrowserUnavailable as e:
        return {"confirmed": False, "evidence": {"error": str(e)}}

    token_keywords = ("csrf", "xsrf", "authenticity", "_token", "anti-forgery", "antiforgery")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        try:
            page.goto(url, timeout=timeout_ms, wait_until="load")
            form = page.query_selector(form_selector)
            if not form:
                browser.close()
                return {"confirmed": False, "evidence": {"error": f"No element matched '{form_selector}'", "url": url}}

            hidden_inputs = form.query_selector_all("input[type=hidden]")
            found_token = False
            token_names = []
            for inp in hidden_inputs:
                name = (inp.get_attribute("name") or inp.get_attribute("id") or "").lower()
                token_names.append(name)
                if any(k in name for k in token_keywords):
                    found_token = True

            cookies = context.cookies()
            samesite_cookies = [c for c in cookies if c.get("sameSite") in ("Strict", "Lax")]
        except Exception as e:
            browser.close()
            return {"confirmed": False, "evidence": {"error": str(e)}}
        browser.close()

    missing_protection = not found_token and not samesite_cookies
    return {
        "confirmed": missing_protection,
        "evidence": {
            "url": url,
            "hidden_input_names": token_names,
            "csrf_token_field_found": found_token,
            "samesite_cookie_count": len(samesite_cookies),
            "total_cookie_count": len(cookies),
        },
    }


def browser_login_flow_test(
    login_url: str,
    username_selector: str,
    password_selector: str,
    submit_selector: str,
    username: str,
    password: str,
    success_indicator: str = None,
    timeout_ms: int = 10000,
) -> dict:
    """
    Automates ONE login attempt with a SINGLE, caller-supplied credential
    pair — never iterates a list, so this cannot be used for credential
    stuffing or brute forcing. Useful for reaching authenticated pages so
    later fuzz/verify calls have a valid session, and for confirming
    whether a login form is vulnerable to things like missing rate
    limiting being visible in the response (not tested here) or whether
    `success_indicator` text appears post-login.
    """
    _check_host(login_url)
    try:
        sync_playwright = _get_playwright()
    except BrowserUnavailable as e:
        return {"success": False, "evidence": {"error": str(e)}}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        try:
            page.goto(login_url, timeout=timeout_ms, wait_until="load")
            page.fill(username_selector, username)
            page.fill(password_selector, password)
            page.click(submit_selector)
            page.wait_for_timeout(1500)
            final_url = page.url
            body_text = page.inner_text("body")
            cookies = context.cookies()
        except Exception as e:
            browser.close()
            return {"success": False, "evidence": {"error": str(e)}}
        browser.close()

    success = True
    if success_indicator:
        success = success_indicator in body_text

    return {
        "success": success,
        "evidence": {
            "final_url": final_url,
            "success_indicator_checked": success_indicator,
            "cookie_names_after_login": [c.get("name") for c in cookies],
        },
    }
