"""
Authorization guard. Every tool call must pass through is_authorized()
before it touches the network. Targets are loaded from scope.txt, one
per line (IP, CIDR, or hostname), '#' for comments.

A new target can be added at runtime (from the CLI or the web GUI), but
only through add_to_scope(), which always requires the caller to have
already confirmed authorization (a CLI flag or a GUI checkbox) and always
writes a UTC timestamp alongside the entry, so there is a permanent,
honest record of when and how each target was added.
"""
from datetime import datetime, timezone
from pathlib import Path

SCOPE_FILE = Path(__file__).resolve().parent.parent / "scope.txt"


def load_scope() -> set[str]:
    if not SCOPE_FILE.exists():
        return set()
    lines = SCOPE_FILE.read_text().splitlines()
    targets = set()
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        # entries may be "target" or "target  # added 2026-...Z"
        targets.add(ln.split("#", 1)[0].strip())
    return {t for t in targets if t}


def is_authorized(target: str) -> bool:
    return target.strip() in load_scope()


def add_to_scope(target: str) -> str:
    """
    Append `target` to scope.txt with a UTC timestamp comment, if it isn't
    already present. The caller is responsible for having already obtained
    an explicit authorization confirmation (CLI flag / GUI checkbox) before
    calling this — this function does not ask again, it only records.
    Returns the target as written.
    """
    target = target.strip()
    if not target:
        raise ValueError("Empty target.")
    if is_authorized(target):
        return target

    if not SCOPE_FILE.exists():
        SCOPE_FILE.touch()

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with SCOPE_FILE.open("a") as f:
        f.write(f"{target}  # added {stamp} via authorization confirmation\n")
    return target
