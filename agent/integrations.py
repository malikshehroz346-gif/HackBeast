"""
Push confirmed findings out to wherever the team actually looks: a Slack
channel, a Jira project, or GitHub Issues — the same "findings flow into
your existing tools" pattern Strix and XBOW both advertise.

Every function here is best-effort and silent-degrade: if the relevant
config isn't set, it returns {"skipped": True, "reason": ...} instead of
raising, so a run with no integrations configured behaves exactly like
before. Each one only ever sends CONFIRMED, evidence-backed findings —
never narrated/candidate ones — because that's all memory.findings ever
contains.
"""
import json

import requests

DEFAULT_TIMEOUT = 15


def _severity_emoji(severity: str) -> str:
    return {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢",
        "Informational": "ℹ️",
        "Unrated": "⚪",
    }.get(severity, "⚪")


def send_to_slack(webhook_url: str | None, memory) -> dict:
    """Post a summary + one line per confirmed finding to a Slack incoming webhook."""
    if not webhook_url:
        return {"skipped": True, "reason": "No Slack webhook URL configured."}
    if not memory.findings:
        text = f"*HackBeast* finished scanning `{memory.target}` — no confirmed findings."
    else:
        lines = [f"*HackBeast* finished scanning `{memory.target}` — {len(memory.findings)} confirmed finding(s):"]
        for f in memory.findings:
            lines.append(f"{_severity_emoji(f['severity'])} *{f['severity']}* — {f['title']}")
        text = "\n".join(lines)

    try:
        resp = requests.post(webhook_url, json={"text": text}, timeout=DEFAULT_TIMEOUT)
        return {"skipped": False, "status_code": resp.status_code, "ok": resp.status_code < 300}
    except requests.RequestException as e:
        return {"skipped": False, "ok": False, "error": str(e)}


def create_jira_issues(
    base_url: str | None,
    email: str | None,
    api_token: str | None,
    project_key: str | None,
    memory,
    min_severity: str = "Medium",
) -> dict:
    """
    Create one Jira issue per confirmed finding at or above `min_severity`,
    via Jira Cloud's REST API (basic auth with an email + API token, the
    standard Atlassian Cloud auth method — never a password).
    """
    if not all([base_url, email, api_token, project_key]):
        return {"skipped": True, "reason": "Jira base_url/email/api_token/project_key not fully configured."}

    order = ["Informational", "Unrated", "Low", "Medium", "High", "Critical"]
    min_rank = order.index(min_severity) if min_severity in order else 0

    created = []
    errors = []
    for f in memory.findings:
        rank = order.index(f["severity"]) if f["severity"] in order else 0
        if rank < min_rank:
            continue
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[HackBeast] {f['severity']}: {f['title']} ({memory.target})",
                "description": (
                    f"{f['description']}\n\n"
                    f"CVSS: {f.get('cvss', 'n/a')}  OWASP: {f.get('owasp_category', 'n/a')}\n\n"
                    f"Evidence:\n{{code:json}}{json.dumps(f['evidence'], indent=2)[:3000]}{{code}}"
                ),
                "issuetype": {"name": "Bug"},
            }
        }
        try:
            resp = requests.post(
                f"{base_url.rstrip('/')}/rest/api/2/issue",
                auth=(email, api_token),
                json=payload,
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code in (200, 201):
                created.append(resp.json().get("key"))
            else:
                errors.append({"title": f["title"], "status": resp.status_code, "body": resp.text[:500]})
        except requests.RequestException as e:
            errors.append({"title": f["title"], "error": str(e)})

    return {"skipped": False, "created": created, "errors": errors}


def create_github_issues(
    token: str | None,
    repo: str | None,  # "owner/name"
    memory,
    min_severity: str = "Medium",
) -> dict:
    """Create one GitHub Issue per confirmed finding at or above `min_severity`."""
    if not token or not repo:
        return {"skipped": True, "reason": "GitHub token/repo not configured."}

    order = ["Informational", "Unrated", "Low", "Medium", "High", "Critical"]
    min_rank = order.index(min_severity) if min_severity in order else 0

    created = []
    errors = []
    for f in memory.findings:
        rank = order.index(f["severity"]) if f["severity"] in order else 0
        if rank < min_rank:
            continue
        body = (
            f"**Target:** `{memory.target}`\n\n"
            f"{f['description']}\n\n"
            f"**CVSS:** {f.get('cvss', 'n/a')}  **OWASP:** {f.get('owasp_category', 'n/a')}\n\n"
            f"<details><summary>Evidence</summary>\n\n```json\n{json.dumps(f['evidence'], indent=2)[:3000]}\n```\n</details>"
        )
        payload = {
            "title": f"[HackBeast] {f['severity']}: {f['title']} ({memory.target})",
            "body": body,
            "labels": ["security", f"severity:{f['severity'].lower()}"],
        }
        try:
            resp = requests.post(
                f"https://api.github.com/repos/{repo}/issues",
                headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
                json=payload,
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 201:
                created.append(resp.json().get("number"))
            else:
                errors.append({"title": f["title"], "status": resp.status_code, "body": resp.text[:500]})
        except requests.RequestException as e:
            errors.append({"title": f["title"], "error": str(e)})

    return {"skipped": False, "created": created, "errors": errors}


def dispatch_all(memory, cfg: dict) -> dict:
    """
    Run whichever integrations are configured in `cfg` (a plain dict of
    env-style keys — see .env.example) and return a combined result for
    logging. Safe to call with an empty/partial cfg; unconfigured
    integrations just report {"skipped": True}.
    """
    results = {}
    results["slack"] = send_to_slack(cfg.get("SLACK_WEBHOOK_URL"), memory)
    results["jira"] = create_jira_issues(
        cfg.get("JIRA_BASE_URL"), cfg.get("JIRA_EMAIL"), cfg.get("JIRA_API_TOKEN"),
        cfg.get("JIRA_PROJECT_KEY"), memory, cfg.get("JIRA_MIN_SEVERITY", "Medium"),
    )
    results["github"] = create_github_issues(
        cfg.get("GITHUB_TOKEN"), cfg.get("GITHUB_REPO"), memory, cfg.get("GITHUB_MIN_SEVERITY", "Medium"),
    )
    return results
