"""
A thin, provider-agnostic wrapper so the agent loop doesn't care which
LLM provider it's talking to. Two paths only:
  - "anthropic": uses Anthropic's native SDK/message format.
  - "openai_compatible": uses the OpenAI SDK pointed at whatever base_url
    was configured — this covers OpenAI, NVIDIA NIM, Groq, Together,
    OpenRouter, Ollama, vLLM, LM Studio, or any other OpenAI-compatible
    endpoint, since they all speak the same /chat/completions format.

Each provider's chat() method returns a normalized dict:
  {"text": str | None, "tool_calls": [{"id", "name", "input"}], "raw": ...}
"""
from agent.config import AgentConfig


class LLMClient:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        if cfg.provider == "anthropic":
            import anthropic
            self._client = anthropic.Anthropic(api_key=cfg.api_key)
        elif cfg.provider == "openai_compatible":
            import openai
            self._client = openai.OpenAI(
                base_url=cfg.base_url,
                api_key=cfg.api_key or "not-needed",
            )
        else:
            raise ValueError(f"Unknown provider: {cfg.provider}")

    def chat(self, messages: list[dict], tools: list[dict], system: str) -> dict:
        if self.cfg.provider == "anthropic":
            return self._chat_anthropic(messages, tools, system)
        return self._chat_openai_compatible(messages, tools, system)

    def _chat_anthropic(self, messages, tools, system):
        resp = self._client.messages.create(
            model=self.cfg.model,
            max_tokens=2000,
            system=system,
            messages=messages,
            tools=tools,
        )
        text, tool_calls = None, []
        for block in resp.content:
            if block.type == "text":
                text = (text or "") + block.text
            elif block.type == "tool_use":
                tool_calls.append({"id": block.id, "name": block.name, "input": block.input})
        return {"text": text, "tool_calls": tool_calls, "raw": resp}

    def _chat_openai_compatible(self, messages, tools, system):
        oi_messages = [{"role": "system", "content": system}] + messages
        oi_tools = [
            {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
            for t in tools
        ]
        resp = self._client.chat.completions.create(
            model=self.cfg.model, messages=oi_messages, tools=oi_tools
        )
        choice = resp.choices[0].message
        tool_calls = []
        for tc in (choice.tool_calls or []):
            import json
            tool_calls.append({"id": tc.id, "name": tc.function.name, "input": json.loads(tc.function.arguments)})
        return {"text": choice.content, "tool_calls": tool_calls, "raw": resp}
