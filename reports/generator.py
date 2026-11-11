"""Turns a Memory object into a readable Markdown report, grouped by severity."""
from datetime import datetime, timezone

from agent.memory import Memory, severity_label

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Unrated"]


def generate_report(memory: Memory) -> str:
    lines = [
        f"# Pentest Report — {memory.target}",
        f"_Started {memory.started_at}, generated {datetime.now(timezone.utc).isoformat()}_",
        "",
        "## Summary",
        f"{len(memory.history)} tool calls across recon/fuzz/verify phases. "
        f"{len(memory.findings)} confirmed, evidence-backed finding(s).",
        "",
    ]

    if memory.findings:
        by_severity: dict[str, list[dict]] = {}
        for f in memory.findings:
            by_severity.setdefault(f["severity"], []).append(f)

        lines.append("## Findings")
        for sev in SEVERITY_ORDER:
            group = by_severity.get(sev)
            if not group:
                continue
            lines.append(f"\n### {sev} ({len(group)})")
            for f in group:
                cvss_str = f"CVSS {f['cvss']}" if f.get("cvss") is not None else "CVSS not rated"
                owasp_str = f" — {f['owasp_category']}" if f.get("owasp_category") else ""
                lines.append(f"\n**{f['title']}** ({cvss_str}{owasp_str})")
                lines.append(f"\n{f['description']}")
                lines.append("\n<details><summary>Evidence</summary>\n")
                lines.append("```json")
                import json
                lines.append(json.dumps(f["evidence"], indent=2)[:3000])
                lines.append("```")
                lines.append("</details>")
    else:
        lines.append("## Findings")
        lines.append("\nNo findings were confirmed with evidence during this run.")

    lines.append("\n## Phase activity log")
    current_phase = None
    for entry in memory.history:
        if entry.get("phase") != current_phase:
            current_phase = entry.get("phase")
            lines.append(f"\n### {current_phase}")
        lines.append(f"- `{entry['tool']}({entry['input']})` → {str(entry['result'])[:200]}")

    report = "\n".join(lines)
    (memory.out_dir / "report.md").write_text(report)
    return report
