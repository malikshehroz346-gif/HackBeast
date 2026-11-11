"""
A persistent, cookie-aware HTTP session the agent can drive manually —
useful for login flows, authenticated endpoints, and IDOR-style probing
where a single stateless request isn't enough.

Every request is scope-checked against the *host* being requested, not
just the original target, so the session can't be used to pivot to an
unauthorized host mid-run.
"""
from urllib.parse import urlparse

import requests

from agent.scope import is_authorized

DEFAULT_TIMEOUT = 15
MAX_BODY_CHARS = 4000


class SessionScopeError(PermissionError):
    pass


class ScopedSession:
    """One persistent requests.Session per target, reused across fuzz-phase calls."""

    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "HackBeast/1.0 (authorized-pentest-agent)"})

    def _check_host(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        # The host actually being requested must itself be authorized. This
        # is the single choke point that stops the agent from pivoting off
        # the authorized target to an unrelated host (SSRF, data
        # exfiltration to an attacker-controlled URL, etc.) — it is NOT
        # satisfied just because the *session* (self.target) was authorized
        # when it was created, since the URL on any given call is whatever
        # the LLM asked for.
        if not is_authorized(host):
            raise SessionScopeError(
                f"Host '{host}' from URL '{url}' is not in scope.txt — refusing to request it."
            )

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: dict | None = None,
        json_body: dict | None = None,
        params: dict | None = None,
        allow_redirects: bool = True,
    ) -> dict:
        self._check_host(url)
        try:
            resp = self.session.request(
                method.upper(),
                url,
                headers=headers,
                data=data,
                json=json_body,
                params=params,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=allow_redirects,
            )
        except requests.RequestException as e:
            return {"error": str(e)}

        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "url": resp.url,
            "redirect_history": [r.status_code for r in resp.history],
            "location": resp.headers.get("Location"),
            "cookies": self.session.cookies.get_dict(),
            "body": resp.text[:MAX_BODY_CHARS],
            "body_truncated": len(resp.text) > MAX_BODY_CHARS,
        }


# One scoped session per target, reused across tool calls within a run.
_SESSIONS: dict[str, ScopedSession] = {}


def get_session(target: str) -> ScopedSession:
    if target not in _SESSIONS:
        _SESSIONS[target] = ScopedSession(target)
    return _SESSIONS[target]


def http_request(
    target: str,
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    data: dict | None = None,
    json_body: dict | None = None,
    params: dict | None = None,
) -> dict:
    """Tool-facing wrapper: make one request through the target's persistent session."""
    return get_session(target).request(method, url, headers=headers, data=data, json_body=json_body, params=params)
