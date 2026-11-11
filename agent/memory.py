"""
Tracks findings and the tool-call history for the current run.

Findings are evidence-required: add_finding() rejects anything without a
non-empty `evidence` dict, so the model can't narrate a vulnerability into
existence — every recorded finding must be backed by output from an actual
verify_* check (agent/verify.py, agent/browser.py).
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class FindingRejected(ValueError):
    pass


# Rough CVSS-bucket thresholds for the report's severity grouping.
def severity_label(cvss: float | None) -> str:
    if cvss is None:
        return "Unrated"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Informational"


class Memory:
    """
    Not just a dumb container: log_tool_call/add_finding are guarded by a
    lock because run_agent() can fan out fuzz+verify phases across several
    discovered hosts in parallel threads (see core.py's parallel host
    fan-out) that all write into the same Memory instance concurrently.
    """

    def __init__(self, target: str):
        self.target = target
        self.findings: list[dict] = []
        self.history: list[dict] = []
        self.phase_log: list[dict] = []  # which phase produced which step
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.out_dir = Path("outputs") / target.replace("/", "_")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log_tool_call(self, phase: str, name: str, input_: dict, result: dict, host: str | None = None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": phase,
            "host": host,
            "tool": name,
            "input": input_,
            "result": result,
        }
        with self._lock:
            self.history.append(entry)

    def add_finding(
        self,
        title: str,
        description: str,
        evidence: dict,
        cvss: float | None = None,
        owasp_category: str | None = None,
        host: str | None = None,
    ) -> dict:
        if not evidence or not isinstance(evidence, dict):
            raise FindingRejected(
                "record_finding rejected: no `evidence` dict provided. "
                "Run a verify_* or browser_* check first and pass its result as evidence."
            )
        finding = {
            "title": title,
            "description": description,
            "evidence": evidence,
            "cvss": cvss,
            "owasp_category": owasp_category,
            "severity": severity_label(cvss),
            "host": host,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self.findings.append(finding)
        return finding

    def save(self) -> None:
        (self.out_dir / "findings.json").write_text(
            json.dumps(
                {
                    "target": self.target,
                    "started_at": self.started_at,
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "findings": self.findings,
                },
                indent=2,
            )
        )
        (self.out_dir / "history.json").write_text(json.dumps(self.history, indent=2))
