"""Known-CVE / signature-based vulnerability scanning — phase 2 (fuzz)."""
from tools.base import ensure_authorized, run_cmd


def nuclei_scan(target: str, severity: str = "medium,high,critical") -> dict:
    """Run community nuclei templates (known-CVE / misconfig detection) against an authorized target."""
    ensure_authorized(target)
    result = run_cmd(["nuclei", "-u", target, "-severity", severity, "-silent"], timeout=600)
    return {"target": target, "raw": result}
