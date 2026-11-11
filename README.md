
# HackBeast

An open-source, autonomous AI pentesting agent — recon, fuzz, verify, report,
built the way tools like [Strix](https://github.com/usestrix/strix) and
XBOW work: an LLM drives real security tools, every claimed vulnerability
has to be backed by evidence from an actual check (not narrated by the
model), and every target has to be explicitly authorized before anything
touches it.

**You are responsible for only ever pointing this at systems you own or
have explicit written authorization to test.** Unauthorized scanning is
illegal in most jurisdictions, and this tool will refuse to run against
anything not in `scope.txt` — there is no way to bypass that from the
GUI or CLI.

---

## How it works

HackBeast runs a single LLM through four sequential phases, each its own
short conversation with a phase-specific system prompt and its own subset
of tools. The previous phase's summary (plus a log of what it actually
ran) is handed forward, so later phases are reasoning from real tool
output, not from what the model remembers saying earlier.

```
 recon  →  fuzz  →  verify  →  report
```

1. **Recon** — maps the attack surface: subdomains (`subfinder`), live
   HTTP(S) hosts (`httpx`), open ports/services (`nmap`), and declared API
   endpoints if you gave it an OpenAPI/Swagger/Postman file.
2. **Fuzz** — looks for *candidate* weaknesses with `nuclei`, `ffuf`,
   `sqlmap` (detection-only), `nikto`, and manual HTTP probing through a
   persistent, cookie-aware session. If you supplied a login/password, it
   can drive a real browser through exactly one login attempt to reach an
   authenticated area — never a list, never brute-forcing.
3. **Verify** — every candidate has to be run through a matching check
   before it can become a finding. `record_finding` is **rejected** if it
   isn't called with a real `evidence` dict taken from one of these:
   - `verify_sqli` — error-signature + boolean-blind differential check
   - `verify_reflected_xss` — unescaped-marker reflection check
   - `verify_idor` — differential response check between your own
     resource id and a different one
   - `verify_open_redirect` — confirms an actual redirect to a safe,
     IANA-reserved test domain (`example.com`)
   - `verify_ssrf` — non-blind heuristic (explicitly flagged as
     inconclusive for blind SSRF, which needs an out-of-band listener)
   - `verify_auth_bypass` — checks whether a response looks the same with
     the auth header stripped
   - `verify_ssti` — sends benign arithmetic expressions (`{{7*7}}`,
     `${7*7}`, `#{7*7}`) and checks whether the server evaluated them to
     `49` rather than reflecting the literal text
   - `verify_command_injection` — an echoed marker plus a benign
     `sleep`-based timing differential; no destructive payloads
   - `verify_xxe` — the same SSRF-style differential approach as
     `verify_ssrf`, applied to an XML external entity, so it never tries
     to read a real local file
   - `verify_secret_exposure` — scans a live response for common
     hardcoded-secret patterns (AWS/API keys, JWTs, PEM private keys,
     Slack/GitHub/Stripe tokens); evidence only ever shows a masked
     excerpt, never the full secret
   - `browser_verify_xss` — loads the page in real headless Chromium and
     checks for actual DOM/JS execution of an injected marker
   - `browser_check_clickjacking` — `X-Frame-Options` / CSP
     `frame-ancestors` check
   - `browser_check_csrf_protection` — looks for a CSRF token field and
     `SameSite` cookies on a form

   All of these use benign markers/canaries, never real exploit payloads.
4. **Report** — the model writes a summary of confirmed findings; this
   phase has no tools, so it cannot invent new ones here either.

The final Markdown report groups findings by severity (derived from the
CVSS score you or the model attaches), shows the OWASP category, and
includes a collapsible evidence block per finding plus a full phase
activity log.

### What makes a finding "confirmed"

```python
def add_finding(self, title, description, evidence, cvss=None, owasp_category=None):
    if not evidence or not isinstance(evidence, dict):
        raise FindingRejected(...)
    ...
```

There's no path from "the model said so" to a line in the report — the
`evidence` dict has to come from one of the `verify_*`/`browser_*`
functions above, which run real requests/browser actions and return real
response data.

### Parallel host fan-out

After recon, the fuzz and verify phases run **concurrently across every
host that's already authorized in `scope.txt`** — the original target
plus any subdomain recon discovered that the operator had separately
pre-authorized. This is the practical, safe version of how Strix's agent
graph and XBOW's thousands of parallel workers scale across an attack
surface: real concurrency, but **authorization is never auto-expanded** —
a subdomain `subfinder` turns up is only ever tested if it was already in
`scope.txt` before the run started. `max_parallel_hosts` (CLI flag or GUI
field, default 3) caps how many run at once in a single pass.

### Scan modes & custom instructions

Three depth/speed presets, same idea as Strix's Quick/Standard/Deep:

| Mode | Step budget per phase | Behavior |
|---|---|---|
| `quick` | 6 | Highest-confidence checks only, skips slow/exhaustive scans |
| `standard` (default) | 15 | Balanced |
| `deep` | 30 | Wider port ranges/wordlists, more parameters checked |

You can also pass free-text custom instructions (CLI `--custom-instructions`,
GUI field) appended to every phase's system prompt — e.g. *"focus on auth
bypass and SSRF only"* — without ever being able to override scope or the
evidence-required finding rule.

### Findings export (Slack / Jira / GitHub Issues)

Confirmed findings can be pushed out automatically after a run — the
same "findings flow into your existing tools" idea both competitors
advertise:
- **Slack** — one summary message via an incoming webhook URL
- **Jira Cloud** — one issue per confirmed finding at/above a minimum
  severity (default Medium)
- **GitHub Issues** — same, as repo issues with `security` +
  `severity:<level>` labels

Configure via the GUI's Integrations panel (saved to `.env`), via
`.env` directly, or per-run with CLI flags (`--slack-webhook`,
`--jira-base-url`/`--jira-email`/`--jira-api-token`/`--jira-project-key`,
`--github-token`/`--github-repo`). All of it is optional and silently
no-ops if unconfigured — this never blocks a run, and it only ever sends
**confirmed**, evidence-backed findings.

### Scope enforcement

Every tool call — CLI wrappers, the HTTP session, and the browser —
checks the *actual host being requested* against `scope.txt` before doing
anything, independent of which target the run was started for. A target
only gets into `scope.txt` after an explicit, timestamped confirmation:

- CLI: `--i-own-this-or-have-authorization`
- GUI: the authorization checkbox on the dashboard

```
testphp.vulnweb.com  # added 2026-03-14T10:02:31Z via authorization confirmation
```

---

## Project layout

```
ai-pentest-agent/
├── main.py                 # CLI entrypoint: banner, naming prompt, GUI launch, headless/CI mode
├── webapp.py                # Flask GUI: dashboard, live SSE log, run-history viewer
├── agent/
│   ├── config.py             # .env load/save, setup wizard, free-text provider/model/base-url
│   ├── llm_client.py          # Anthropic SDK path + generic OpenAI-compatible path
│   ├── core.py                 # the 4-phase agent loop, tool schemas, system prompts
│   ├── memory.py                # Memory (history/findings), evidence-required add_finding
│   ├── scope.py                  # scope.txt load/check/add, timestamped
│   ├── http_session.py            # ScopedSession — cookie-aware, per-request host scope check
│   ├── verify.py                    # the 6 HTTP-level evidence-producing checks
│   ├── browser.py                    # the 4 Playwright-driven real-browser checks
│   └── specs.py                       # OpenAPI/Swagger/Postman spec parsing
├── tools/
│   ├── base.py               # ensure_authorized / ensure_installed / run_cmd
│   ├── recon.py                # subfinder, httpx, nmap
│   ├── scan.py                   # nuclei
│   └── exploit.py                  # sqlmap (detection-only), ffuf, nikto
├── reports/
│   └── generator.py          # Markdown report, grouped by severity, CVSS/OWASP tags
├── scope.txt                # authorized targets (append-only, timestamped)
├── requirements.txt
├── Dockerfile                # sandboxed runtime with all tools preinstalled
├── docker-compose.yml
└── .env.example
```

---

## Setup on Windows (development)

1. Install Python 3.11+ and [VS Code](https://code.visualstudio.com/).
2. Clone or open the project folder in VS Code.
3. Open a terminal in VS Code:
   ```
   python -m venv venv
   venv\Scripts\activate
   python -m pip install -r requirements.txt
   python -m playwright install chromium
   ```
   If `pip.exe` is blocked by Windows Application Control / Smart App
   Control, always invoke pip as a module (`python -m pip ...`) as above —
   that goes through the allowed `python.exe` instead of the standalone
   `pip.exe` binary.
4. Push to your own private GitHub repo and continue from there, or just
   keep developing locally.

## Setup on Kali Linux (running real scans)

Kali already ships `nmap`, and usually `sqlmap`/`nikto`; you'll want the
ProjectDiscovery tools and `ffuf` too:

```bash
sudo apt update && sudo apt install -y nmap sqlmap nikto ffuf golang-go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH="$PATH:$(go env GOPATH)/bin"   # add this to ~/.bashrc too

git clone https://github.com/<you>/AI-PENTEST-AGENT.git
cd AI-PENTEST-AGENT
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install --with-deps chromium
```

Or skip all of the above and use Docker instead (see below) — it bundles
every tool for you.

## Running it

```bash
python main.py
```

With no arguments you get the Strix-style flow: a banner, a prompt to
name your agent (default **HackBeast**), then the web GUI launches
automatically and opens in your browser at `http://127.0.0.1:5000`. From
there: save your LLM config (any provider name, any model string, an
optional custom base URL), enter a target, tick the authorization
checkbox for anything new, and start the assessment — you'll see the
recon → fuzz → verify → report phases stream live. The **Run History**
page lists every past assessment with its finding count and top severity,
and lets you open the full report for any of them.

### CLI usage

```bash
# first-time provider/model/API-key setup, no GUI
python main.py --setup

# run a scan directly from the terminal
python main.py --target testphp.vulnweb.com --i-own-this-or-have-authorization

# seed recon from an API spec, and test one login flow
python main.py --target api.example.com --i-own-this-or-have-authorization \
    --spec-file ./openapi.json --username demo --password demo123

# CI mode: no console noise, a JSON summary to stdout, exit 1 if anything was confirmed
python main.py --target staging.example.com --i-own-this-or-have-authorization --headless
```

`--headless` is meant for CI pipelines: wire it into a pipeline step and
let the exit code gate the build.

### Any LLM provider

There's no fixed list — `anthropic` gets the native SDK path; anything
else (`openai`, `nvidia`, `groq`, `together`, `openrouter`, `ollama`, your
own vLLM/LM Studio box, anything else with an OpenAI-compatible API) goes
through a generic path using whatever base URL and model string you type
in. The setup wizard and GUI show a few presets as hints only — you can
always type something else.

### Docker (sandboxed, all tools preincluded)

```bash
cp .env.example .env     # fill in your LLM provider/model/key, or do it from the GUI after first boot
docker compose up --build
```

Opens the GUI at `http://127.0.0.1:5000`. The container has `nmap`,
`sqlmap`, `nikto`, `ffuf`, the ProjectDiscovery Go tools, and headless
Chromium already installed, and keeps the agent's scans isolated from
your host filesystem/network namespace. `scope.txt`, `.env`, and
`outputs/` are mounted so your authorization list, config, and reports
persist across container restarts.

---

## Honest limitations

- Parallel fan-out covers fuzz+verify across already-authorized hosts, but
  recon itself is still a single pass, and there's no full agent-graph /
  pub-sub orchestration layer like Strix's — this is a handful of
  concurrent conversations, not thousands of coordinated micro-agents.
- `verify_ssrf` and `verify_xxe` cannot prove *blind* SSRF/XXE (no
  out-of-band listener); both say so in their own output.
- There's no source-code (white-box/SAST) scanning mode — this is
  black-box/DAST only, same as before this batch of additions.
- No per-scan Docker sandbox around individual exploit actions yet — the
  provided `Dockerfile` isolates the whole agent process from your host,
  but doesn't spin up a fresh, destroyed-after-use container per scan the
  way Strix does.
- No automatic post-fix retest workflow — every run starts from zero;
  re-scan manually once a fix ships.
- `sqlmap_test` is deliberately capped to detection-only flags; nothing
  here will dump data or spawn a shell for you.
- Browser checks degrade gracefully (`{"error": ...}`) if Playwright or
  its Chromium binary isn't installed — the rest of the pipeline still
  runs, just without DOM-level confirmation.
- No authentication on the local GUI — it's meant to run on
  `127.0.0.1` / your own machine, not be exposed to an untrusted network.

## License

See `LICENSE`.
