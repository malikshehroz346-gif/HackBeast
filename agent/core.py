"""
The agent loop: four explicit phases, closer to how Strix separates
recon/exploitation/validation and how XBOW uses a coordinator dispatching
focused workers, though still a handful of LLM conversations rather than
a full agent graph or thousands of workers:

  1. recon   — map the attack surface (subdomains, live hosts, open ports,
               optionally seeded from an OpenAPI/Postman spec).
  2. fuzz    — look for *candidate* weaknesses (nuclei, ffuf, sqlmap,
               nikto, manual HTTP probing, an optional login-flow setup).
  3. verify  — every candidate must be run through a matching verify_* or
               browser_* check before it can become a finding.
               record_finding is rejected without an evidence dict.
  4. report  — the model summarizes confirmed findings and stops; no
               tools are offered in this phase.

Each phase is its own short LLM conversation with a phase-specific system
prompt and tool subset — the previous phase's final summary (plus a
compact log of what it actually ran) is handed forward as context.

Parallel fan-out: after recon, fuzz+verify run concurrently across every
host recon discovered that is ALREADY authorized in scope.txt (never a
host that merely showed up in a subfinder result — authorization is never
auto-expanded; a discovered subdomain only gets tested if the operator
had it in scope already, e.g. by adding a wildcard-style set of hosts
ahead of time). This is the practical, safe version of what XBOW does
with thousands of parallel workers and Strix does with its agent graph.
"""
import concurrent.futures
from functools import partial

from rich.console import Console

from agent.config import AgentConfig
from agent.http_session import http_request
from agent.llm_client import LLMClient
from agent.memory import FindingRejected, Memory
from agent.scope import is_authorized
from agent.specs import parse_api_spec
from agent import verify as verify_mod
from tools import exploit, recon, scan

console = Console()

try:
    from agent import browser as browser_mod
    BROWSER_AVAILABLE = True
except Exception:
    browser_mod = None
    BROWSER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Scan-mode presets — Strix-style quick/standard/deep depth control
# ---------------------------------------------------------------------------

SCAN_MODE_PRESETS = {
    "quick": {
        "max_steps": 6,
        "prompt_suffix": (
            "Work fast: prioritize the highest-confidence checks only and stop as "
            "soon as you have a reasonable picture. Skip slow/exhaustive scans "
            "(full port ranges, large wordlists, every parameter on every page) — "
            "cover the obvious attack surface only."
        ),
    },
    "standard": {"max_steps": 15, "prompt_suffix": ""},
    "deep": {
        "max_steps": 30,
        "prompt_suffix": (
            "Be thorough: use wider port ranges, larger wordlists where available, "
            "and check more parameters and endpoints than you normally would before "
            "moving to the next phase. Prefer completeness over speed."
        ),
    },
}


# ---------------------------------------------------------------------------
# Tool schemas, grouped by phase
# ---------------------------------------------------------------------------

RECON_TOOLS = [
    {
        "name": "subfinder_enum",
        "description": "Enumerate subdomains for an authorized domain.",
        "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
    },
    {
        "name": "httpx_probe",
        "description": "Probe a list of authorized hosts for live HTTP(S) services.",
        "input_schema": {"type": "object", "properties": {"targets": {"type": "array", "items": {"type": "string"}}}, "required": ["targets"]},
    },
    {
        "name": "nmap_scan",
        "description": "Service/version scan of an authorized target.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "ports": {"type": "string", "enum": ["top-1000", "all"]}},
            "required": ["target"],
        },
    },
    {
        "name": "parse_api_spec",
        "description": "Parse a local OpenAPI/Swagger or Postman Collection file into a list of declared endpoints, to seed recon instead of guessing.",
        "input_schema": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]},
    },
]

FUZZ_TOOLS = [
    {
        "name": "nuclei_scan",
        "description": "Run nuclei's known-CVE / misconfiguration templates against the target.",
        "input_schema": {"type": "object", "properties": {"severity": {"type": "string"}}, "required": []},
    },
    {
        "name": "ffuf_fuzz",
        "description": "Directory/parameter fuzz a URL. The url must contain the literal word FUZZ where values should be substituted, e.g. https://target/FUZZ",
        "input_schema": {"type": "object", "properties": {"url_with_fuzz_keyword": {"type": "string"}, "wordlist": {"type": "string"}}, "required": ["url_with_fuzz_keyword"]},
    },
    {
        "name": "sqlmap_test",
        "description": "Run a light, detection-only sqlmap scan (no dumping/exfiltration) against a single URL to flag SQLi candidates for later verification.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "nikto_scan",
        "description": "General web-server misconfiguration scan.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": []},
    },
    {
        "name": "http_request",
        "description": "Make one request through a persistent, cookie-aware session for this target — use for manual probing, login flows, or authenticated endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                "headers": {"type": "object"},
                "data": {"type": "object"},
                "json_body": {"type": "object"},
                "params": {"type": "object"},
            },
            "required": ["url"],
        },
    },
]

VERIFY_TOOLS = [
    {
        "name": "verify_sqli",
        "description": "Error-based + boolean-differential SQLi check on one URL parameter. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "method": {"type": "string"}}, "required": ["url", "param"]},
    },
    {
        "name": "verify_reflected_xss",
        "description": "Checks whether a unique marker reflects back UNescaped through a parameter (raw-HTTP level, not DOM execution — see browser_verify_xss for that). Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "method": {"type": "string"}}, "required": ["url", "param"]},
    },
    {
        "name": "verify_idor",
        "description": "Compares the response for the caller's own resource id against a different probe id. url_template must contain {id}. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url_template": {"type": "string"}, "own_id": {"type": "string"}, "probe_id": {"type": "string"}, "method": {"type": "string"}}, "required": ["url_template", "own_id", "probe_id"]},
    },
    {
        "name": "verify_open_redirect",
        "description": "Checks whether setting a parameter to a safe external test domain (example.com) actually causes a redirect there. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "method": {"type": "string"}}, "required": ["url", "param"]},
    },
    {
        "name": "verify_ssrf",
        "description": "Non-blind SSRF heuristic: compares the response when a parameter points at an internal URL vs. a garbage host. Inconclusive results don't rule out blind SSRF. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "internal_probe": {"type": "string"}, "method": {"type": "string"}}, "required": ["url", "param"]},
    },
    {
        "name": "verify_auth_bypass",
        "description": "Checks whether an endpoint still returns a similar 2xx response when the auth header is stripped. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string"}, "auth_header_name": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "verify_ssti",
        "description": "Server-Side Template Injection check: sends benign arithmetic expressions in common template syntaxes and checks whether the server evaluated them (e.g. 7*7 -> 49). Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "method": {"type": "string"}}, "required": ["url", "param"]},
    },
    {
        "name": "verify_command_injection",
        "description": "OS command injection check using an echoed marker and a benign timing (sleep) differential — no destructive payloads. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "method": {"type": "string"}}, "required": ["url", "param"]},
    },
    {
        "name": "verify_xxe",
        "description": "XXE check using an SSRF-style differential (internal vs. garbage external-entity URL) — does not attempt to read local files. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string"}, "content_type": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "verify_secret_exposure",
        "description": "Scans a live HTTP response (headers + body) for common hardcoded-secret patterns (AWS/API keys, JWTs, private keys, Slack/GitHub/Stripe tokens). Evidence only ever contains a masked excerpt, never the full secret. Returns {confirmed, evidence}.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "record_finding",
        "description": "Record a CONFIRMED finding. REQUIRES an `evidence` object taken directly from a verify_* or browser_* tool result — calls without real evidence are rejected. Optionally include a 0-10 cvss estimate and an owasp_category label (e.g. 'A03:2021-Injection').",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "evidence": {"type": "object"},
                "cvss": {"type": "number"},
                "owasp_category": {"type": "string"},
            },
            "required": ["title", "description", "evidence"],
        },
    },
]

if BROWSER_AVAILABLE:
    VERIFY_TOOLS += [
        {
            "name": "browser_verify_xss",
            "description": "Loads the URL in a real headless browser and checks for actual JS/DOM execution of an injected marker — stronger confirmation than verify_reflected_xss alone. Returns {confirmed, evidence}.",
            "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}}, "required": ["url"]},
        },
        {
            "name": "browser_check_clickjacking",
            "description": "Checks X-Frame-Options / CSP frame-ancestors on a page. Returns {confirmed, evidence}.",
            "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        },
        {
            "name": "browser_check_csrf_protection",
            "description": "Loads a page, inspects its first form for a CSRF token field and checks for SameSite cookies. Returns {confirmed, evidence}.",
            "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "form_selector": {"type": "string"}}, "required": ["url"]},
        },
    ]
    # browser_login_flow_test is only added to the tool list per-host, and
    # only when the operator actually supplied credentials — see
    # _build_login_tool_schema() below. The LLM never sees or supplies the
    # password: the schema has no username/password fields, and the real
    # pair is bound into the implementation with functools.partial, so it
    # can't leak into the model's context.


BASE_SYSTEM_PROMPTS = {
    "recon": """You are the RECON phase of an authorized penetration-testing agent. \
Your only job is to map the attack surface of the given target: subdomains, live \
HTTP(S) hosts, open ports/services, and declared API endpoints if a spec file is \
given. Do not attempt to find or verify vulnerabilities yet. When you have enough \
of a map to hand off, stop calling tools and write a concise summary of what you \
found (hosts, live services, interesting endpoints) for the next phase.""",
    "fuzz": """You are the FUZZ phase of an authorized penetration-testing agent, \
focused on ONE specific host. You've been given a recon summary below. Your job is \
to find CANDIDATE weaknesses using nuclei, ffuf, sqlmap, nikto, and manual HTTP \
probing — candidates only, not confirmed findings. If credentials were provided, \
you may use browser_login_flow_test ONCE to reach an authenticated area. When \
you've gathered enough candidates (specific URLs + parameters worth checking), stop \
calling tools and summarize them clearly — list exact URLs and parameter names so \
the verify phase can act on them precisely.""",
    "verify": """You are the VERIFY phase of an authorized penetration-testing agent, \
focused on ONE specific host. You've been given a list of candidate weaknesses from \
the fuzz phase. For each one, call the matching verify_* or browser_* tool to get \
real evidence — this includes verify_ssti, verify_command_injection, verify_xxe, and \
verify_secret_exposure where relevant, not just the classic injection checks. Only \
call record_finding for a candidate where the matching check returned confirmed: \
true — record_finding is rejected if you don't pass its real evidence dict through. \
Do not record anything you haven't actually verified. When done, stop calling tools \
and briefly summarize what was confirmed and what was tried but did not confirm.""",
    "report": """You are the REPORT phase. Write a clear, concise summary of the \
confirmed findings for this assessment across all hosts tested, grouped by severity, \
plus one short line on anything notable that was tried but not confirmed. Do not \
invent findings beyond what's listed.""",
}


def _build_system_prompts(scan_mode: str, custom_instructions: str | None) -> dict:
    preset = SCAN_MODE_PRESETS.get(scan_mode, SCAN_MODE_PRESETS["standard"])
    extra = f"\n\n{preset['prompt_suffix']}" if preset["prompt_suffix"] else ""
    if custom_instructions and custom_instructions.strip():
        extra += (
            f"\n\nOperator's custom instructions for this run (follow these as a "
            f"priority, but never go outside the authorized scope): "
            f"{custom_instructions.strip()}"
        )
    return {phase: base + extra for phase, base in BASE_SYSTEM_PROMPTS.items()}


def _build_login_tool_schema() -> dict:
    return {
        "name": "browser_login_flow_test",
        "description": "Automates exactly ONE login attempt, using the single credential pair the operator supplied out-of-band (never iterates a list — not for brute forcing), to reach an authenticated session for further testing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "login_url": {"type": "string"},
                "username_selector": {"type": "string"},
                "password_selector": {"type": "string"},
                "submit_selector": {"type": "string"},
                "success_indicator": {"type": "string"},
            },
            "required": ["login_url", "username_selector", "password_selector", "submit_selector"],
        },
    }


def _summarize_tool_calls(history_slice: list[dict]) -> str:
    lines = []
    for h in history_slice:
        lines.append(f"- {h['tool']}({h['input']}) -> {str(h['result'])[:300]}")
    return "\n".join(lines) if lines else "(no tool calls)"


def _run_phase(
    phase: str,
    cfg: AgentConfig,
    client: LLMClient,
    memory: Memory,
    tools: list[dict],
    tool_impl: dict,
    seed_message: str,
    max_steps: int,
    emit,
    system_prompts: dict,
    host: str | None = None,
) -> str:
    messages = [{"role": "user", "content": seed_message}]
    final_text = ""
    phase_start = len(memory.history)

    for step in range(max_steps):
        emit("step", f"[{phase}] step {step + 1}/{max_steps}")
        reply = client.chat(messages=messages, tools=tools, system=system_prompts[phase])

        if reply["text"]:
            emit("agent", f"[{phase}] {reply['text']}")
            final_text = reply["text"]

        if not reply["tool_calls"]:
            break

        messages.append({"role": "assistant", "content": reply.get("raw").content if cfg.provider == "anthropic" else reply["text"] or ""})

        for call in reply["tool_calls"]:
            fn = tool_impl.get(call["name"])
            if fn is None:
                result = {"error": f"Unknown tool {call['name']}"}
            else:
                try:
                    result = fn(**call["input"])
                except FindingRejected as e:
                    result = {"error": str(e)}
                except Exception as e:
                    result = {"error": str(e)}

            emit("tool", f"[{phase}] {call['name']}({call['input']}) -> {str(result)[:300]}")
            memory.log_tool_call(phase, call["name"], call["input"], result, host=host)

            if cfg.provider == "anthropic":
                messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": call["id"], "content": str(result)}]})
            else:
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": str(result)})

    phase_history = [h for h in memory.history[phase_start:] if h.get("host") == host and h.get("phase") == phase]
    return final_text or _summarize_tool_calls(phase_history)


def _extract_authorized_hosts(recon_entries: list[dict], target: str) -> list[str]:
    """
    Pull subdomains subfinder_enum discovered during recon out of the
    phase's tool-call history, but ONLY keep ones already authorized in
    scope.txt — this never auto-expands what's in scope, it just notices
    when the operator had already authorized more than one host ahead of
    time (e.g. several subdomains of a program) so fuzz/verify can cover
    them in parallel instead of the model having to ask for each one by
    name.
    """
    candidates = {target}
    for entry in recon_entries:
        if entry.get("tool") == "subfinder_enum":
            result = entry.get("result")
            if isinstance(result, dict):
                for sd in result.get("subdomains", []) or []:
                    sd = sd.strip()
                    if sd:
                        candidates.add(sd)
    return sorted(h for h in candidates if is_authorized(h))


def _run_fuzz_and_verify_for_host(
    host: str,
    cfg: AgentConfig,
    memory: Memory,
    recon_summary: str,
    credentials: dict | None,
    system_prompts: dict,
    max_steps: int,
    emit,
) -> tuple[str, str]:
    """Runs the fuzz then verify phase for one host, with its own LLM client and tool bindings."""

    def host_emit(event: str, text: str) -> None:
        emit(event, f"[{host}] {text}")

    client = LLMClient(cfg)

    tool_impl_fuzz = {
        "nuclei_scan": partial(scan.nuclei_scan, host),
        "ffuf_fuzz": partial(exploit.ffuf_fuzz, target_host=host),
        "sqlmap_test": partial(exploit.sqlmap_test, target_host=host),
        "nikto_scan": partial(exploit.nikto_scan, host),
        "http_request": partial(http_request, host),
    }
    tool_impl_verify = {
        "verify_sqli": partial(verify_mod.verify_sqli, host),
        "verify_reflected_xss": partial(verify_mod.verify_reflected_xss, host),
        "verify_idor": partial(verify_mod.verify_idor, host),
        "verify_open_redirect": partial(verify_mod.verify_open_redirect, host),
        "verify_ssrf": partial(verify_mod.verify_ssrf, host),
        "verify_auth_bypass": partial(verify_mod.verify_auth_bypass, host),
        "verify_ssti": partial(verify_mod.verify_ssti, host),
        "verify_command_injection": partial(verify_mod.verify_command_injection, host),
        "verify_xxe": partial(verify_mod.verify_xxe, host),
        "verify_secret_exposure": partial(verify_mod.verify_secret_exposure, host),
        "record_finding": lambda **kw: memory.add_finding(host=host, **kw),
    }
    if BROWSER_AVAILABLE:
        tool_impl_verify["browser_verify_xss"] = browser_mod.browser_verify_xss
        tool_impl_verify["browser_check_clickjacking"] = browser_mod.browser_check_clickjacking
        tool_impl_verify["browser_check_csrf_protection"] = browser_mod.browser_check_csrf_protection

    fuzz_tools = list(FUZZ_TOOLS)
    has_creds = bool(BROWSER_AVAILABLE and credentials and credentials.get("username") and credentials.get("password"))
    if has_creds:
        fuzz_tools = fuzz_tools + [_build_login_tool_schema()]
        tool_impl_fuzz["browser_login_flow_test"] = partial(
            browser_mod.browser_login_flow_test,
            username=credentials["username"],
            password=credentials["password"],
        )

    fuzz_seed = f"Target host: {host}.\n\nRecon summary (for the whole assessment):\n{recon_summary}\n\nFind candidate weaknesses on this host now."
    if has_creds:
        fuzz_seed += (
            "\n\nA login credential pair has been supplied by the operator out-of-band. "
            "If you find a login form worth testing, call browser_login_flow_test with the "
            "page's selectors — the credentials will be used automatically, you don't need "
            "(and won't be given) the actual username/password values."
        )
    fuzz_summary = _run_phase("fuzz", cfg, client, memory, fuzz_tools, tool_impl_fuzz, fuzz_seed, max_steps, host_emit, system_prompts, host=host)

    verify_seed = f"Target host: {host}.\n\nCandidates from the fuzz phase:\n{fuzz_summary}\n\nVerify each one now."
    verify_summary = _run_phase("verify", cfg, client, memory, VERIFY_TOOLS, tool_impl_verify, verify_seed, max_steps, host_emit, system_prompts, host=host)

    return fuzz_summary, verify_summary


def run_agent(
    target: str,
    cfg: AgentConfig,
    log_fn=None,
    spec_file: str | None = None,
    credentials: dict | None = None,
    scan_mode: str = "standard",
    custom_instructions: str | None = None,
    max_parallel_hosts: int = 3,
) -> Memory:
    """
    Run the full recon -> fuzz -> verify -> report pipeline against
    `target`.

    `spec_file` (optional) is a local OpenAPI/Swagger/Postman file path to
    seed recon. `credentials` (optional) is a single
    {"username":..., "password":...} pair the fuzz phase may use for ONE
    login attempt via browser_login_flow_test. `scan_mode` is one of
    "quick"/"standard"/"deep" (see SCAN_MODE_PRESETS) and controls depth
    (step budget) and how the model is instructed to trade off speed vs.
    thoroughness. `custom_instructions` is free text appended to every
    phase's system prompt (e.g. "focus on auth bypass and SSRF only").
    `max_parallel_hosts` caps how many already-authorized hosts (the
    original target plus any subdomains recon found that were ALREADY in
    scope.txt — authorization is never auto-expanded) get their fuzz+verify
    phases run concurrently.
    """
    def emit(event: str, text: str) -> None:
        if log_fn:
            log_fn(event, text)
        else:
            console.print(text)

    if not is_authorized(target):
        raise PermissionError(f"'{target}' is not authorized in scope.txt.")

    client = LLMClient(cfg)
    memory = Memory(target)

    preset = SCAN_MODE_PRESETS.get(scan_mode, SCAN_MODE_PRESETS["standard"])
    effective_max_steps = preset["max_steps"]
    system_prompts = _build_system_prompts(scan_mode, custom_instructions)

    tool_impl_recon = {
        "subfinder_enum": recon.subfinder_enum,
        "httpx_probe": recon.httpx_probe,
        "nmap_scan": recon.nmap_scan,
        "parse_api_spec": parse_api_spec,
    }

    # --- Phase 1: recon (always runs once, for the whole assessment) ---
    recon_seed = f"Authorized target: {target}."
    if spec_file:
        recon_seed += f" An API spec file is available at: {spec_file} — parse it first with parse_api_spec."
    recon_phase_start = len(memory.history)
    recon_summary = _run_phase("recon", cfg, client, memory, RECON_TOOLS, tool_impl_recon, recon_seed, effective_max_steps, emit, system_prompts)
    recon_entries = memory.history[recon_phase_start:]

    # --- Phases 2+3: fuzz + verify, fanned out across every already-authorized host ---
    hosts = _extract_authorized_hosts(recon_entries, target)
    hosts_to_run = hosts[:max(1, max_parallel_hosts)]
    skipped_hosts = hosts[max(1, max_parallel_hosts):]

    if len(hosts) > 1:
        emit("step", f"{len(hosts)} authorized host(s) in play: {', '.join(hosts)}")
    if skipped_hosts:
        emit(
            "step",
            f"Running fuzz+verify on {len(hosts_to_run)} host(s) this pass "
            f"(max_parallel_hosts={max_parallel_hosts}); not covered this run: {', '.join(skipped_hosts)}",
        )

    host_summaries: dict[str, tuple[str, str]] = {}
    if len(hosts_to_run) == 1:
        h = hosts_to_run[0]
        host_summaries[h] = _run_fuzz_and_verify_for_host(h, cfg, memory, recon_summary, credentials, system_prompts, effective_max_steps, emit)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts_to_run)) as ex:
            futures = {
                ex.submit(
                    _run_fuzz_and_verify_for_host, h, cfg, memory, recon_summary, credentials, system_prompts, effective_max_steps, emit
                ): h
                for h in hosts_to_run
            }
            for fut in concurrent.futures.as_completed(futures):
                h = futures[fut]
                try:
                    host_summaries[h] = fut.result()
                except Exception as e:
                    emit("error", f"[{h}] fuzz/verify pipeline errored: {e}")
                    host_summaries[h] = (f"(errored: {e})", "(not completed)")

    combined_verify_summary = "\n\n".join(f"[{h}]\n{vsum}" for h, (_, vsum) in host_summaries.items())

    # --- Phase 4: report (no tools) ---
    findings_text = "\n".join(
        f"- [{f['severity']}] {f['title']} (host: {f.get('host') or target}): {f['description']}" for f in memory.findings
    ) or "(none confirmed)"
    report_seed = f"Target: {target}.\n\nConfirmed findings:\n{findings_text}\n\nVerify-phase notes per host:\n{combined_verify_summary}\n\nWrite the final summary."
    report_text = _run_phase("report", cfg, client, memory, [], {}, report_seed, 1, emit, system_prompts)

    memory.save()
    emit("done", report_text or f"Assessment complete. {len(memory.findings)} confirmed finding(s). Report: {memory.out_dir / 'report.md'}")
    return memory
