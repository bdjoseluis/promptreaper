"""Cliente LLM minimalista y sin dependencias (solo stdlib).

Soporta Groq y Google Gemini via REST. Se usa para dos roles opcionales:
  - atacante-LLM adaptativo (genera el siguiente turno del ataque)
  - juez-LLM (dictamina si un intento tuvo exito)

Si no hay ninguna clave disponible, `get_llm()` devuelve None y PromptReaper
degrada con elegancia a la libreria estatica de payloads + juez heuristico.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str
    ok: bool = True
    error: str = ""


class LLMClient:
    provider = "none"

    def complete(self, system: str, user: str, temperature: float = 0.7,
                 max_tokens: int = 1024) -> LLMResult:  # pragma: no cover - interface
        raise NotImplementedError

    def available(self) -> bool:
        return True


def _post_json(url: str, payload: dict, headers: dict, timeout: int = 45) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class GroqClient(LLMClient):
    provider = "groq"

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model

    def complete(self, system, user, temperature=0.7, max_tokens=1024) -> LLMResult:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        try:
            out = _post_json(url, payload, headers)
            text = out["choices"][0]["message"]["content"]
            return LLMResult(text=text, provider=self.provider, model=self.model)
        except (urllib.error.URLError, KeyError, IndexError, ValueError) as exc:
            return LLMResult("", self.provider, self.model, ok=False, error=str(exc))


class GeminiClient(LLMClient):
    provider = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        self.api_key = api_key
        self.model = model

    def complete(self, system, user, temperature=0.7, max_tokens=1024) -> LLMResult:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        headers = {"Content-Type": "application/json"}
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        try:
            out = _post_json(url, payload, headers)
            parts = out["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
            return LLMResult(text=text, provider=self.provider, model=self.model)
        except (urllib.error.URLError, KeyError, IndexError, ValueError) as exc:
            return LLMResult("", self.provider, self.model, ok=False, error=str(exc))


def get_llm(prefer: str | None = None) -> LLMClient | None:
    """Devuelve un cliente LLM segun las claves disponibles en el entorno.

    Orden por defecto: Groq (rapido y con free tier generoso) -> Gemini.
    `prefer` puede forzar "groq" o "gemini". Devuelve None si no hay claves.
    """
    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip() or \
        os.environ.get("GOOGLE_API_KEY", "").strip()

    order = ["groq", "gemini"]
    if prefer == "gemini":
        order = ["gemini", "groq"]
    elif prefer == "groq":
        order = ["groq", "gemini"]

    for prov in order:
        if prov == "groq" and groq_key:
            model = os.environ.get("PROMPTREAPER_GROQ_MODEL", "llama-3.3-70b-versatile")
            return GroqClient(groq_key, model)
        if prov == "gemini" and gemini_key:
            model = os.environ.get("PROMPTREAPER_GEMINI_MODEL", "gemini-2.0-flash")
            return GeminiClient(gemini_key, model)
    return None
