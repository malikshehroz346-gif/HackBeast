#!/usr/bin/env python3
"""
Local web GUI for HackBeast.

Run with:
    python webapp.py

Then open http://127.0.0.1:5000 in your browser. You can configure the
LLM provider/model/API key, enter a target (with an explicit authorization
checkbox for anything new), optionally provide a single login credential
pair or an API spec file, and watch the agent's recon/fuzz/verify/report
phases stream live. A Run History page lists past assessments.

This is a local-only tool: binds to 127.0.0.1 by default (set WEB_HOST=0.0.0.0
when running inside the provided Docker container) and has no authentication,
so don't expose it to an untrusted network as-is.
"""
import html
import json
import os
import queue
import threading
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request

from agent.config import ENV_PATH, KNOWN_PRESETS, load_agent_name, load_config
from agent.core import SCAN_MODE_PRESETS, run_agent
from agent.integrations import dispatch_all
from agent.scope import add_to_scope, is_authorized, load_scope
from dotenv import load_dotenv, set_key

app = Flask(__name__)

JOBS: dict[str, dict] = {}
OUTPUTS_DIR = Path("outputs")


BASE_STYLE = """
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text); font-family: -apple-system, Segoe UI, sans-serif;
    margin: 0; padding: 2rem; max-width: 960px; margin-inline: auto;
  }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  h2 { font-size: 1.1rem; margin: 1.5rem 0 .5rem; }
  a { color: var(--accent); }
  .sub { color: var(--muted); margin-bottom: 1.5rem; font-size: .9rem; }
  .nav { margin-bottom: 1.5rem; font-size: .9rem; }
  .nav a { margin-right: 1rem; }
  .panel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 1.25rem; margin-bottom: 1.25rem;
  }
  label { display: block; font-size: .85rem; color: var(--muted); margin: .75rem 0 .25rem; }
  input, select, textarea {
    width: 100%; padding: .5rem .6rem; background: #010409; color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; font-size: .9rem; font-family: inherit;
  }
  .row { display: flex; gap: .75rem; }
  .row > div { flex: 1; }
  button {
    margin-top: 1rem; padding: .6rem 1.2rem; border: none; border-radius: 6px;
    background: var(--accent); color: #0d1117; font-weight: 600; cursor: pointer; font-size: .9rem;
  }
  button:disabled { opacity: .5; cursor: not-allowed; }
  #log {
    background: #010409; border: 1px solid var(--border); border-radius: 8px;
    padding: 1rem; height: 420px; overflow-y: auto; font-family: ui-monospace, monospace;
    font-size: .8rem; white-space: pre-wrap; line-height: 1.5;
  }
  .ev-step { color: var(--accent); font-weight: 600; margin-top: .5rem; }
  .ev-agent { color: var(--text); }
  .ev-tool { color: var(--yellow); }
  .ev-done { color: var(--green); font-weight: 600; }
  .ev-error { color: var(--red); }
  .scope-note { font-size: .8rem; color: var(--muted); margin-top: .4rem; }
  .authbox { display:flex; align-items:flex-start; gap:.5rem; margin-top:1rem; color: var(--text); font-size:.85rem; }
  .authbox input { width: auto; margin-top: .2rem; }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th, td { text-align: left; padding: .5rem; border-bottom: 1px solid var(--border); }
  .sev-Critical { color: var(--red); font-weight: 700; }
  .sev-High { color: #ff8c69; font-weight: 600; }
  .sev-Medium { color: var(--yellow); }
  .sev-Low { color: var(--muted); }
  pre.report { background: #010409; border: 1px solid var(--border); border-radius: 8px; padding: 1rem; white-space: pre-wrap; font-size: .85rem; }
</style>
"""

NAV = '<div class="nav"><a href="/">Dashboard</a><a href="/runs">Run History</a></div>'


INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ agent_name }}</title>
""" + BASE_STYLE + """
</head>
<body>
  <h1>{{ agent_name }}</h1>
  <div class="sub">Autonomous pentesting agent — recon, fuzz, verify, report. Authorized targets only.</div>
  """ + NAV + """

  <div class="panel">
    <strong>LLM configuration</strong>
    <div class="row">
      <div>
        <label>Provider name (any — preset or custom)</label>
        <input id="provider" value="{{ cfg.label if cfg else 'anthropic' }}" list="presets">
        <datalist id="presets">{% for p in presets %}<option value="{{p}}">{% endfor %}</datalist>
      </div>
      <div>
        <label>Model</label>
        <input id="model" value="{{ cfg.model if cfg else '' }}" placeholder="e.g. claude-sonnet-5-5">
      </div>
    </div>
    <div class="row">
      <div>
        <label>Base URL (leave blank for Anthropic / Ollama)</label>
        <input id="base_url" value="{{ cfg.base_url if cfg and cfg.base_url else '' }}" placeholder="https://api.groq.com/openai/v1">
      </div>
      <div>
        <label>API key (leave blank to keep saved key)</label>
        <input id="api_key" type="password" placeholder="••••••••">
      </div>
    </div>
    <button onclick="saveConfig()">Save configuration</button>
    <span id="save-status" style="margin-left:.75rem; color: var(--muted); font-size:.85rem;"></span>
  </div>

  <div class="panel">
    <strong>Target</strong>
    <label>Target (domain, host, or URL)</label>
    <input id="target" placeholder="testphp.vulnweb.com">
    <div class="scope-note" id="scope-note">Already authorized: {{ scope_list|join(', ') if scope_list else '(none yet)' }}</div>

    <label class="authbox">
      <input type="checkbox" id="authorize_new">
      <span>
        I own this target, or I have explicit written authorization to test it
        (e.g. a signed scope-of-work, a bug-bounty program's published scope, or
        a system I personally control). Checking this adds the target to
        <code>scope.txt</code> with a timestamp before the scan starts.
        Unauthorized scanning is illegal in most jurisdictions — this box is
        not optional for new targets.
      </span>
    </label>

    <div class="row" style="margin-top:1rem;">
      <div>
        <label>Scan mode</label>
        <select id="scan_mode">
          <option value="quick">Quick — fast, highest-confidence checks only</option>
          <option value="standard" selected>Standard</option>
          <option value="deep">Deep — thorough, slower</option>
        </select>
      </div>
      <div>
        <label>Max parallel hosts</label>
        <input id="max_parallel_hosts" type="number" min="1" max="10" value="3">
        <div class="scope-note">Fuzz+verify run concurrently across this many already-authorized hosts (target + any in-scope subdomains recon finds) — never auto-expands scope.</div>
      </div>
    </div>
    <label>Custom instructions (optional)</label>
    <input id="custom_instructions" placeholder="e.g. focus on auth bypass and SSRF only">

    <details style="margin-top:1rem;">
      <summary style="cursor:pointer; color: var(--muted); font-size:.85rem;">Optional: spec file / single login credentials</summary>
      <label>Local OpenAPI/Swagger/Postman file path (seeds recon)</label>
      <input id="spec_file" placeholder="/path/to/openapi.json">
      <div class="row">
        <div><label>Username (one login attempt only, no brute forcing)</label><input id="username"></div>
        <div><label>Password</label><input id="password" type="password"></div>
      </div>
    </details>

    <button id="start-btn" onclick="startAgent()">Start assessment</button>
  </div>

  <div class="panel">
    <strong>Integrations (optional)</strong>
    <div class="sub" style="margin-bottom:.5rem;">Push confirmed findings to Slack / Jira / GitHub Issues when a run finishes.</div>
    <label>Slack incoming webhook URL</label>
    <input id="slack_webhook" placeholder="https://hooks.slack.com/services/...">
    <div class="row">
      <div><label>Jira base URL</label><input id="jira_base_url" placeholder="https://yourorg.atlassian.net" value="{{ integrations.JIRA_BASE_URL or '' }}"></div>
      <div><label>Jira project key</label><input id="jira_project_key" placeholder="SEC" value="{{ integrations.JIRA_PROJECT_KEY or '' }}"></div>
    </div>
    <div class="row">
      <div><label>Jira email</label><input id="jira_email" value="{{ integrations.JIRA_EMAIL or '' }}"></div>
      <div><label>Jira API token</label><input id="jira_api_token" type="password"></div>
    </div>
    <div class="row">
      <div><label>GitHub token (repo scope)</label><input id="github_token" type="password"></div>
      <div><label>GitHub repo (owner/name)</label><input id="github_repo" placeholder="yourorg/yourrepo" value="{{ integrations.GITHUB_REPO or '' }}"></div>
    </div>
    <div class="scope-note">Webhook URLs/tokens are write-only here once saved — fields show blank again on reload, but the saved value is kept unless you overwrite it.</div>
    <button onclick="saveIntegrations()">Save integrations</button>
    <span id="integrations-status" style="margin-left:.75rem; color: var(--muted); font-size:.85rem;"></span>
  </div>

  <div class="panel">
    <strong>Live log</strong>
    <div id="log">Waiting to start...</div>
  </div>

<script>
async function saveConfig() {
  const body = {
    provider: document.getElementById('provider').value.trim(),
    model: document.getElementById('model').value.trim(),
    base_url: document.getElementById('base_url').value.trim(),
    api_key: document.getElementById('api_key').value,
  };
  const res = await fetch('/api/config', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const data = await res.json();
  document.getElementById('save-status').textContent = data.ok ? 'Saved.' : ('Error: ' + data.error);
}

async function saveIntegrations() {
  const body = {
    slack_webhook: document.getElementById('slack_webhook').value.trim(),
    jira_base_url: document.getElementById('jira_base_url').value.trim(),
    jira_project_key: document.getElementById('jira_project_key').value.trim(),
    jira_email: document.getElementById('jira_email').value.trim(),
    jira_api_token: document.getElementById('jira_api_token').value,
    github_token: document.getElementById('github_token').value,
    github_repo: document.getElementById('github_repo').value.trim(),
  };
  const res = await fetch('/api/integrations', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const data = await res.json();
  document.getElementById('integrations-status').textContent = data.ok ? 'Saved.' : ('Error: ' + data.error);
}

async function startAgent() {
  const target = document.getElementById('target').value.trim();
  if (!target) { alert('Enter a target first.'); return; }
  const btn = document.getElementById('start-btn');
  btn.disabled = true;
  const log = document.getElementById('log');
  log.textContent = '';

  const body = {
    target,
    authorize_new: document.getElementById('authorize_new').checked,
    spec_file: document.getElementById('spec_file').value.trim() || null,
    username: document.getElementById('username').value.trim() || null,
    password: document.getElementById('password').value || null,
    scan_mode: document.getElementById('scan_mode').value,
    custom_instructions: document.getElementById('custom_instructions').value.trim() || null,
    max_parallel_hosts: parseInt(document.getElementById('max_parallel_hosts').value, 10) || 3,
  };
  const res = await fetch('/api/start', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const data = await res.json();
  if (!data.ok) { log.textContent = 'Error: ' + data.error; btn.disabled = false; return; }
  document.getElementById('scope-note').textContent = 'Already authorized: ' + (data.scope_list || []).join(', ');

  const evtSource = new EventSource('/api/stream/' + data.job_id);
  evtSource.onmessage = (e) => {
    const payload = JSON.parse(e.data);
    const span = document.createElement('div');
    span.className = 'ev-' + payload.event;
    span.textContent = (payload.event === 'step' ? '' : '[' + payload.event + '] ') + payload.text;
    log.appendChild(span);
    log.scrollTop = log.scrollHeight;
    if (payload.event === 'done' || payload.event === 'error') {
      evtSource.close();
      btn.disabled = false;
    }
  };
  evtSource.onerror = () => { evtSource.close(); btn.disabled = false; };
}
</script>
</body>
</html>
"""

RUNS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ agent_name }} — Run History</title>
""" + BASE_STYLE + """
</head>
<body>
  <h1>{{ agent_name }} — Run History</h1>
  """ + NAV + """
  <div class="panel">
    {% if runs %}
    <table>
      <tr><th>Target</th><th>Findings</th><th>Highest severity</th><th></th></tr>
      {% for r in runs %}
      <tr>
        <td>{{ r.target }}</td>
        <td>{{ r.count }}</td>
        <td class="sev-{{ r.top_severity }}">{{ r.top_severity }}</td>
        <td><a href="/runs/{{ r.dir_name }}">View report</a></td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p style="color: var(--muted);">No runs yet.</p>
    {% endif %}
  </div>
</body>
</html>
"""

RUN_DETAIL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ agent_name }} — {{ target }}</title>
""" + BASE_STYLE + """
</head>
<body>
  <h1>{{ target }}</h1>
  """ + NAV + """
  <div class="panel">
    <pre class="report">{{ report_text }}</pre>
  </div>
</body>
</html>
"""


def _load_integrations_cfg() -> dict:
    """Non-secret fields only, for pre-filling the form — never echoes tokens/passwords back."""
    if ENV_PATH.exists():
        load_dotenv(ENV_PATH, override=True)
    return {
        "JIRA_BASE_URL": os.getenv("JIRA_BASE_URL"),
        "JIRA_PROJECT_KEY": os.getenv("JIRA_PROJECT_KEY"),
        "JIRA_EMAIL": os.getenv("JIRA_EMAIL"),
        "GITHUB_REPO": os.getenv("GITHUB_REPO"),
    }


@app.route("/")
def index():
    try:
        cfg = load_config()
    except SystemExit:
        cfg = None
    scope_list = sorted(load_scope())
    agent_name = load_agent_name()
    return render_template_string(
        INDEX_HTML, cfg=cfg, presets=list(KNOWN_PRESETS.keys()), scope_list=scope_list,
        agent_name=agent_name, integrations=_load_integrations_cfg(),
    )


SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Unrated": 0}


@app.route("/runs")
def runs_index():
    runs = []
    if OUTPUTS_DIR.exists():
        for d in sorted(OUTPUTS_DIR.iterdir()):
            findings_file = d / "findings.json"
            if not findings_file.exists():
                continue
            try:
                data = json.loads(findings_file.read_text())
            except Exception:
                continue
            findings = data.get("findings", [])
            top = "Unrated"
            if findings:
                top = max((f.get("severity", "Unrated") for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0))
            runs.append({"target": data.get("target", d.name), "count": len(findings), "top_severity": top, "dir_name": d.name})
    return render_template_string(RUNS_HTML, runs=runs, agent_name=load_agent_name())


@app.route("/runs/<dir_name>")
def run_detail(dir_name):
    safe_name = Path(dir_name).name  # prevent path traversal
    report_file = OUTPUTS_DIR / safe_name / "report.md"
    if not report_file.exists():
        return Response("Report not found.", status=404)
    return render_template_string(
        RUN_DETAIL_HTML, target=safe_name, report_text=html.escape(report_file.read_text()), agent_name=load_agent_name()
    )


@app.route("/api/config", methods=["POST"])
def api_config():
    data = request.get_json(force=True)
    provider = (data.get("provider") or "anthropic").strip().lower()
    model = (data.get("model") or "").strip()
    base_url = (data.get("base_url") or "").strip()
    api_key = data.get("api_key") or ""

    if not model:
        return jsonify(ok=False, error="Model name is required.")

    if not ENV_PATH.exists():
        ENV_PATH.touch()

    set_key(str(ENV_PATH), "LLM_LABEL", provider)
    set_key(str(ENV_PATH), "LLM_PROVIDER", "anthropic" if provider == "anthropic" else "openai_compatible")
    set_key(str(ENV_PATH), "LLM_MODEL", model)
    if api_key:
        set_key(str(ENV_PATH), "LLM_API_KEY", api_key)
    if base_url:
        set_key(str(ENV_PATH), "LLM_BASE_URL", base_url)
    set_key(str(ENV_PATH), "MAX_STEPS", "15")

    return jsonify(ok=True)


@app.route("/api/integrations", methods=["POST"])
def api_integrations():
    data = request.get_json(force=True)
    if not ENV_PATH.exists():
        ENV_PATH.touch()

    # Non-secret fields: save whatever's given, including clearing to empty.
    for key, form_key in [("JIRA_BASE_URL", "jira_base_url"), ("JIRA_PROJECT_KEY", "jira_project_key"), ("JIRA_EMAIL", "jira_email"), ("GITHUB_REPO", "github_repo")]:
        set_key(str(ENV_PATH), key, (data.get(form_key) or "").strip())

    # Secret fields: only overwrite if a new value was actually typed, so
    # leaving the (blank, write-only) field alone on a later save doesn't
    # wipe out a previously-saved webhook URL or token.
    for key, form_key in [("SLACK_WEBHOOK_URL", "slack_webhook"), ("JIRA_API_TOKEN", "jira_api_token"), ("GITHUB_TOKEN", "github_token")]:
        val = data.get(form_key)
        if val:
            set_key(str(ENV_PATH), key, val)

    return jsonify(ok=True)


@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    authorize_new = bool(data.get("authorize_new"))
    spec_file = data.get("spec_file") or None
    username = data.get("username") or None
    password = data.get("password") or None
    scan_mode = data.get("scan_mode") or "standard"
    if scan_mode not in SCAN_MODE_PRESETS:
        scan_mode = "standard"
    custom_instructions = data.get("custom_instructions") or None
    try:
        max_parallel_hosts = max(1, int(data.get("max_parallel_hosts") or 3))
    except (TypeError, ValueError):
        max_parallel_hosts = 3

    if not target:
        return jsonify(ok=False, error="No target given.")

    if not is_authorized(target):
        if not authorize_new:
            return jsonify(
                ok=False,
                error=(
                    f"'{target}' isn't authorized yet. Tick the authorization "
                    f"checkbox to confirm you own it or have written permission "
                    f"to test it, then retry."
                ),
            )
        add_to_scope(target)

    try:
        cfg = load_config()
    except SystemExit:
        return jsonify(ok=False, error="No LLM configured yet — save configuration first.")

    credentials = {"username": username, "password": password} if (username and password) else None

    if ENV_PATH.exists():
        load_dotenv(ENV_PATH, override=True)
    integration_cfg = {
        "SLACK_WEBHOOK_URL": os.getenv("SLACK_WEBHOOK_URL"),
        "JIRA_BASE_URL": os.getenv("JIRA_BASE_URL"),
        "JIRA_EMAIL": os.getenv("JIRA_EMAIL"),
        "JIRA_API_TOKEN": os.getenv("JIRA_API_TOKEN"),
        "JIRA_PROJECT_KEY": os.getenv("JIRA_PROJECT_KEY"),
        "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN"),
        "GITHUB_REPO": os.getenv("GITHUB_REPO"),
    }

    job_id = str(uuid.uuid4())
    log_queue: queue.Queue = queue.Queue()
    JOBS[job_id] = {"queue": log_queue, "target": target}

    def worker():
        def log_fn(event: str, text: str) -> None:
            log_queue.put({"event": event, "text": text})
        try:
            memory = run_agent(
                target, cfg, log_fn=log_fn, spec_file=spec_file, credentials=credentials,
                scan_mode=scan_mode, custom_instructions=custom_instructions, max_parallel_hosts=max_parallel_hosts,
            )
            if any(integration_cfg.values()):
                log_fn("step", "Dispatching confirmed findings to configured integrations...")
                results = dispatch_all(memory, integration_cfg)
                for name, result in results.items():
                    if not result.get("skipped"):
                        log_fn("step", f"{name}: {result}")
        except Exception as e:
            log_queue.put({"event": "error", "text": str(e)})
        log_queue.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return jsonify(ok=True, job_id=job_id, scope_list=sorted(load_scope()))


@app.route("/api/stream/<job_id>")
def api_stream(job_id):
    job = JOBS.get(job_id)
    if not job:
        return Response("job not found", status=404)

    def generate():
        q = job["queue"]
        while True:
            item = q.get()
            if item is None:
                break
            yield f"data: {json.dumps(item)}\n\n"
        yield "event: end\ndata: {}\n\n"

    return Response(generate(), mimetype="text/event-stream")


if __name__ == "__main__":
    host = os.getenv("WEB_HOST", "127.0.0.1")
    print(f"{load_agent_name()} GUI running at http://{host}:5000")
    app.run(host=host, port=5000, debug=False, threaded=True)
