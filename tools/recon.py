"""Reconnaissance tool wrappers — phase 1 (recon)."""
import subprocess

from tools.base import ensure_authorized, ensure_installed, run_cmd


def subfinder_enum(domain: str) -> dict:
    """Enumerate subdomains for a domain already present in scope.txt."""
    ensure_authorized(domain)
    result = run_cmd(["subfinder", "-d", domain, "-silent"], timeout=180)
    subdomains = [ln for ln in result["stdout"].splitlines() if ln.strip()]
    return {"domain": domain, "subdomains": subdomains, "raw": result}


def httpx_probe(targets: list[str]) -> dict:
    """Probe a list of hosts/subdomains for live HTTP(S) services."""
    for t in targets:
        ensure_authorized(t)
    ensure_installed("httpx")
    proc_input = "\n".join(targets)
    try:
        proc = subprocess.run(
            ["httpx", "-silent", "-status-code", "-title"],
            input=proc_input, capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return {"targets": targets, "raw_stdout": "", "error": "Timed out after 180s"}
    return {"targets": targets, "raw_stdout": proc.stdout}


def nmap_scan(target: str, ports: str = "top-1000") -> dict:
    """Service/version scan a single authorized target (moved here from scan.py — it's recon, not a vuln scan)."""
    ensure_authorized(target)
    port_flag = ["-p-"] if ports == "all" else ["--top-ports", "1000"]
    result = run_cmd(["nmap", "-sV", *port_flag, target], timeout=600)
    return {"target": target, "ports": ports, "raw": result}
