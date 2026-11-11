#!/usr/bin/env python3
"""
HackBeast — autonomous AI pentesting agent. CLI entrypoint.

Just run it with no arguments for the Strix-style flow: name your agent,
and its web dashboard opens automatically in your browser.

    python main.py

First-time LLM setup (CLI wizard instead of the GUI form):
    python main.py --setup

Run a scan straight from the command line, no GUI:
    python main.py --target 192.168.56.10 --i-own-this-or-have-authorization

Headless / CI mode — prints a JSON summary, exits 1 if anything was confirmed:
    python main.py --target 192.168.56.10 --headless --i-own-this-or-have-authorization

Deep scan, custom focus, findings pushed to Slack/Jira/GitHub Issues:
    python main.py --target api.example.com --i-own-this-or-have-authorization \
        --scan-mode deep --custom-instructions "focus on auth bypass and SSRF" \
        --slack-webhook https://hooks.slack.com/... \
        --github-token ghp_... --github-repo yourorg/yourrepo

Launch only the web GUI without the naming prompt:
    python webapp.py
"""
import argparse
import json
import sys
import threading
import time
import webbrowser

from rich.console import Console
from rich.prompt import Prompt

from agent.config import DEFAULT_AGENT_NAME, load_agent_name, load_config, run_setup_wizard, save_agent_name
from agent.core import run_agent
from agent.integrations import dispatch_all
from agent.scope import add_to_scope, is_authorized
from reports.generator import generate_report

console = Console()

BANNER = r"""
[bold red]
  _    _            _    ____                 _
 | |  | |          | |  |  _ \               | |
 | |__| | __ _  ___ | | _| |_) | ___  __ _ ___| |_
 |  __  |/ _` |/ __|| |/ /  _ < / _ \/ _` / __| __|
 | |  | | (_| | (__ |   <| |_) |  __/ (_| \__ \ |_
 |_|  |_|\__,_|\___||_|\_\____/ \___|\__,_|___/\__|
[/bold red]
[dim]Autonomous AI pentesting agent — recon, fuzz, verify, report[/dim]
"""


def launch_gui(agent_name: str) -> None:
    """Start the Flask GUI in-process and open it in the default browser."""
    save_agent_name(agent_name)

    # Import here so `python main.py --target ...` (pure CLI mode) never
    # needs Flask installed just to run a scan.
    import webapp

    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open("http://127.0.0.1:5000")
        except Exception:
            pass  # headless Linux box with no browser configured — not fatal

    threading.Thread(target=open_browser, daemon=True).start()
    console.print(f"\n[bold green]{agent_name}[/bold green] is starting at [underline]http://127.0.0.1:5000[/underline] ...")
    console.print("[dim]Press CTRL+C to stop.[/dim]\n")
    webapp.app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


def run_cli_scan(args) -> None:
    if not is_authorized(args.target):
        if not args.i_own_this_or_have_authorization:
            console.print(
                f"[red]'{args.target}' isn't authorized yet.[/red] Re-run with "
                f"[bold]--i-own-this-or-have-authorization[/bold] to confirm you own "
                f"it or have explicit written permission to test it — this adds it "
                f"to scope.txt with a timestamp before scanning. Unauthorized "
                f"scanning is illegal in most jurisdictions."
            )
            raise SystemExit(1)
        added = add_to_scope(args.target)
        if not args.headless:
            console.print(f"[yellow]Added '{added}' to scope.txt (confirmed via CLI flag).[/yellow]")

    cfg = load_config(cli_label=args.provider, cli_model=args.model)

    credentials = None
    if args.username and args.password:
        credentials = {"username": args.username, "password": args.password}

    run_kwargs = dict(
        spec_file=args.spec_file,
        credentials=credentials,
        scan_mode=args.scan_mode,
        custom_instructions=args.custom_instructions,
        max_parallel_hosts=args.max_parallel_hosts,
    )

    if not args.headless:
        console.print(f"[bold]Using {cfg.label} ({cfg.provider}) / {cfg.model} — scan mode: {args.scan_mode}[/bold]")
        memory = run_agent(args.target, cfg, **run_kwargs)
    else:
        # Suppress rich console noise in headless/CI mode — only the final JSON matters.
        memory = run_agent(args.target, cfg, log_fn=lambda *_: None, **run_kwargs)

    generate_report(memory)

    integration_cfg = {
        "SLACK_WEBHOOK_URL": args.slack_webhook,
        "JIRA_BASE_URL": args.jira_base_url,
        "JIRA_EMAIL": args.jira_email,
        "JIRA_API_TOKEN": args.jira_api_token,
        "JIRA_PROJECT_KEY": args.jira_project_key,
        "GITHUB_TOKEN": args.github_token,
        "GITHUB_REPO": args.github_repo,
    }
    if any(integration_cfg.values()):
        integration_results = dispatch_all(memory, integration_cfg)
        if not args.headless:
            for name, result in integration_results.items():
                if result.get("skipped"):
                    continue
                console.print(f"[dim]{name}: {result}[/dim]")

    if args.headless:
        summary = {
            "target": args.target,
            "finding_count": len(memory.findings),
            "findings": memory.findings,
            "report_path": str(memory.out_dir / "report.md"),
        }
        print(json.dumps(summary, indent=2))
        sys.exit(1 if memory.findings else 0)
    else:
        console.print(f"\n[green]Report written to {memory.out_dir / 'report.md'}[/green]")
        console.print(f"[green]{len(memory.findings)} confirmed finding(s).[/green]")


def main() -> None:
    parser = argparse.ArgumentParser(description="HackBeast — autonomous AI pentesting agent")
    parser.add_argument("--setup", action="store_true", help="Run the interactive provider/model/API key setup wizard (CLI only, no GUI)")
    parser.add_argument("--target", help="Target to scan — runs a scan directly in the terminal, no GUI")
    parser.add_argument(
        "--i-own-this-or-have-authorization",
        action="store_true",
        help=(
            "Required for any --target not already in scope.txt. Confirms you own the "
            "target or have explicit written authorization to test it; adds it to "
            "scope.txt with a timestamp before scanning."
        ),
    )
    parser.add_argument("--provider", help="Override provider label for this run (e.g. anthropic, nvidia, groq, my-vllm-box)")
    parser.add_argument("--model", help="Override LLM model for this run")
    parser.add_argument("--spec-file", help="Path to a local OpenAPI/Swagger/Postman file to seed recon")
    parser.add_argument("--username", help="Single username for one login-flow test (fuzz phase) — paired with --password")
    parser.add_argument("--password", help="Single password for one login-flow test (fuzz phase) — paired with --username")
    parser.add_argument("--headless", action="store_true", help="CI mode: no banner/log noise, prints a JSON summary, exits 1 if any finding was confirmed")
    parser.add_argument("--no-gui", action="store_true", help="Skip the agent-name prompt and GUI auto-launch")
    parser.add_argument("--name", help="Agent name to use (skips the naming prompt)")
    parser.add_argument("--scan-mode", choices=["quick", "standard", "deep"], default="standard", help="Depth/speed tradeoff for this run (default: standard)")
    parser.add_argument("--custom-instructions", help="Free text appended to every phase's system prompt, e.g. 'focus on auth bypass and SSRF only'")
    parser.add_argument("--max-parallel-hosts", type=int, default=3, help="Cap on how many already-authorized hosts (target + in-scope subdomains recon found) run fuzz+verify concurrently (default: 3)")
    parser.add_argument("--slack-webhook", help="Post a findings summary to this Slack incoming webhook URL after the run")
    parser.add_argument("--jira-base-url", help="Jira Cloud base URL, e.g. https://yourorg.atlassian.net, to create one issue per confirmed finding")
    parser.add_argument("--jira-email", help="Jira account email (used with --jira-api-token for basic auth)")
    parser.add_argument("--jira-api-token", help="Jira API token (Atlassian Cloud) — never your account password")
    parser.add_argument("--jira-project-key", help="Jira project key to create issues in, e.g. SEC")
    parser.add_argument("--github-token", help="GitHub personal access token with repo scope, to create one Issue per confirmed finding")
    parser.add_argument("--github-repo", help="owner/repo to create GitHub Issues in")
    args = parser.parse_args()

    if args.setup:
        run_setup_wizard()
        return

    if args.target:
        run_cli_scan(args)
        return

    # Default: Strix-style flow — ask for a name, then open the GUI.
    console.print(BANNER)
    if args.no_gui:
        return

    if args.name:
        agent_name = args.name.strip() or DEFAULT_AGENT_NAME
    else:
        saved = load_agent_name()
        agent_name = Prompt.ask("Name your agent", default=saved).strip() or DEFAULT_AGENT_NAME

    launch_gui(agent_name)


if __name__ == "__main__":
    main()
