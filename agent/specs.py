"""
Parses an OpenAPI 3 / Swagger 2 / Postman Collection file so the agent can
seed recon with the application's *declared* endpoints instead of relying
purely on crawling/guessing — the same idea as Strix accepting
OpenAPI/Swagger/Postman input. This is a lightweight, dependency-free
parser (just json/yaml), not a full spec validator: it extracts
{method, path, params} tuples and nothing more.
"""
import json
from pathlib import Path


def _load_raw(file_path: str) -> dict:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Spec file not found: {file_path}")
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as e:
            raise RuntimeError("Parsing a YAML spec requires pyyaml: pip install pyyaml") from e
        return yaml.safe_load(text)
    return json.loads(text)


def _parse_openapi(spec: dict) -> list[dict]:
    endpoints = []
    for path, path_item in (spec.get("paths") or {}).items():
        for method, op in path_item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "options", "head"):
                continue
            params = [p.get("name") for p in (op.get("parameters") or []) if p.get("name")]
            endpoints.append({"method": method.upper(), "path": path, "params": params, "summary": op.get("summary", "")})
    return endpoints


def _parse_postman(spec: dict) -> list[dict]:
    endpoints = []

    def walk(items):
        for item in items:
            if "item" in item:  # folder — recurse
                walk(item["item"])
                continue
            req = item.get("request")
            if not isinstance(req, dict):
                continue
            method = req.get("method", "GET")
            url = req.get("url")
            raw_path = url.get("raw") if isinstance(url, dict) else url
            query = url.get("query") if isinstance(url, dict) else []
            params = [q.get("key") for q in (query or []) if isinstance(q, dict) and q.get("key")]
            endpoints.append({"method": method.upper(), "path": raw_path or "", "params": params, "summary": item.get("name", "")})

    walk(spec.get("item", []))
    return endpoints


def parse_api_spec(file_path: str) -> dict:
    """
    Returns {"format": "openapi"|"postman"|"unknown", "endpoints": [...]}.
    Never raises on a recognized-but-partial spec — missing fields just
    produce fewer endpoints, since this is only meant to seed recon, not
    to validate the spec itself.
    """
    spec = _load_raw(file_path)

    if "openapi" in spec or "swagger" in spec:
        return {"format": "openapi", "endpoints": _parse_openapi(spec)}
    if "item" in spec and ("info" in spec):
        return {"format": "postman", "endpoints": _parse_postman(spec)}
    return {"format": "unknown", "endpoints": []}
