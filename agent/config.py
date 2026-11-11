"""
Handles loading config from .env and the interactive --setup wizard that
lets the user pick an LLM provider, model, and API key on first run.

Supports any provider with an OpenAI-compatible API (which covers almost
everything: OpenAI, NVIDIA NIM, Groq, Together, Fireworks, OpenRouter,
local Ollama, vLLM, LM Studio, etc.) via a free-text base URL, plus a
first-class Anthropic path since it uses its own SDK/message format.
"""
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv, set_key
from rich.console import Console
from rich.prompt import Prompt

console = Console()

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

DEFAULT_AGENT_NAME = "HackBeast"


def load_agent_name() -> str:
    """Return the saved agent name, or the default if none is set yet."""
    load_dotenv(ENV_PATH, override=True)
    return os.getenv("AGENT_NAME", DEFAULT_AGENT_NAME).strip() or DEFAULT_AGENT_NAME


def save_agent_name(name: str) -> None:
    if not ENV_PATH.exists():
        ENV_PATH.touch()
    set_key(str(ENV_PATH), "AGENT_NAME", name.strip() or DEFAULT_AGENT_NAME)

# Shown only as hints in the wizard — none of this restricts what you can type.
KNOWN_PRESETS = {
    "anthropic": {"base_url": None, "example_model": "claude-sonnet-5-5"},
    "openai": {"base_url": "https://api.openai.com/v1", "example_model": "gpt-4o"},
    "nvidia": {"base_url": "https://integrate.api.nvidia.com/v1", "example_model": "nvidia/nemotron-3-super-120b-a12b"},
    "groq": {"base_url": "https://api.groq.com/openai/v1", "example_model": "llama-3.1-8b-instant"},
    "together": {"base_url": "https://api.together.xyz/v1", "example_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "example_model": "anthropic/claude-sonnet-4.5"},
    "ollama": {"base_url": "http://localhost:11434/v1", "example_model": "llama3.1"},
}


@dataclass
class AgentConfig:
    provider: str          # "anthropic" or "openai_compatible"
    label: str              # the name you typed, e.g. "nvidia", "groq", "my-vllm-box"
    model: str
    api_key: str | None
    base_url: str | None    # only used when provider == "openai_compatible"
    max_steps: int


def run_setup_wizard() -> None:
    """Interactive first-run setup: pick ANY provider, model, and API key."""
    console.print("\n[bold cyan]AI Pentest Agent — setup[/bold cyan]")
    console.print(
        "[dim]Known presets: "
        + ", ".join(KNOWN_PRESETS.keys())
        + " — or type any other name for a custom OpenAI-compatible endpoint.[/dim]\n"
    )

    label = Prompt.ask("Provider name (any name — preset or custom)", default="anthropic").strip().lower()
    preset = KNOWN_PRESETS.get(label)

    uses_anthropic_sdk = label == "anthropic"

    base_url = None
    if not uses_anthropic_sdk:
        default_url = preset["base_url"] if preset else ""
        base_url = Prompt.ask(
            "API base URL (OpenAI-compatible endpoint)",
            default=default_url,
        ).strip()

    default_model = preset["example_model"] if preset else ""
    model = Prompt.ask(
        "Model name (type exactly as the provider expects it)",
        default=default_model,
    ).strip()

    api_key = ""
    needs_key = not (label == "ollama" or (base_url and "localhost" in base_url))
    if needs_key:
        api_key = Prompt.ask("API key for this provider (input hidden)", password=True)

    if not ENV_PATH.exists():
        ENV_PATH.touch()

    set_key(str(ENV_PATH), "LLM_LABEL", label)
    set_key(str(ENV_PATH), "LLM_PROVIDER", "anthropic" if uses_anthropic_sdk else "openai_compatible")
    set_key(str(ENV_PATH), "LLM_MODEL", model)
    set_key(str(ENV_PATH), "LLM_API_KEY", api_key)
    if base_url:
        set_key(str(ENV_PATH), "LLM_BASE_URL", base_url)
    set_key(str(ENV_PATH), "MAX_STEPS", "15")

    console.print(f"\n[green]Saved config to {ENV_PATH}[/green]")
    console.print("You can re-run `python main.py --setup` (or use the web GUI) any time to change this.\n")


def load_config(cli_label: str | None = None, cli_model: str | None = None) -> AgentConfig:
    """Load config from .env, with optional CLI overrides for this run only."""
    load_dotenv(ENV_PATH, override=True)

    label = (cli_label or os.getenv("LLM_LABEL", "anthropic")).lower()
    provider = os.getenv("LLM_PROVIDER", "anthropic" if label == "anthropic" else "openai_compatible")
    model = cli_model or os.getenv("LLM_MODEL", "")
    api_key = os.getenv("LLM_API_KEY")
    base_url = os.getenv("LLM_BASE_URL")

    if not model:
        console.print("[red]No model configured. Run `python main.py --setup` or use the web GUI first.[/red]")
        raise SystemExit(1)

    if provider == "openai_compatible" and not base_url:
        console.print("[red]No base URL configured. Run `python main.py --setup` or use the web GUI first.[/red]")
        raise SystemExit(1)

    return AgentConfig(
        provider=provider,
        label=label,
        model=model,
        api_key=api_key,
        base_url=base_url,
        max_steps=int(os.getenv("MAX_STEPS", "15")),
    )
