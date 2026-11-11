"""Shared helper for running external CLI security tools safely."""
import shutil
import subprocess

from agent.scope import is_authorized


class ScopeError(PermissionError):
    pass


def ensure_authorized(target: str) -> None:
    if not is_authorized(target):
        raise ScopeError(
            f"'{target}' is not in scope.txt. Add it explicitly (via --i-own-this-or-have-authorization "
            f"on the CLI, or the authorization checkbox in the GUI) before scanning it."
        )


def ensure_installed(binary: str) -> None:
    if shutil.which(binary) is None:
        raise RuntimeError(f"Required tool '{binary}' not found on PATH.")


def run_cmd(args: list[str], timeout: int = 300) -> dict:
    ensure_installed(args[0])
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": f"Timed out after {timeout}s"}
