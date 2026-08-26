"""Objetivos (targets): el bajo nivel que envia un prompt y devuelve la respuesta.

Dos implementaciones:
  - HttpTarget: chatbot expuesto por HTTP/JSON (caso real).
  - CallableTarget: un callable Python en proceso (labs y tests, sin red).
"""

from __future__ import annotations

import importlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass


class TargetError(Exception):
    pass


@dataclass
class TargetResponse:
    text: str
    raw: str = ""
    ok: bool = True
    error: str = ""
    status: int = 0


class Target:
    name = "target"

    def send(self, prompt: str) -> TargetResponse:  # pragma: no cover - interface
        raise NotImplementedError


def _dig(obj, dot_path: str):
    """Extrae un valor de un dict/list anidado con notacion 'a.b.0.c'."""
    cur = obj
    for part in dot_path.split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur


class HttpTarget(Target):
    def __init__(self, cfg):
        self.cfg = cfg
        self.name = cfg.name

    def send(self, prompt: str) -> TargetResponse:
        # Inserta el prompt saneado para JSON en la plantilla del cuerpo.
        safe = json.dumps(prompt)[1:-1]  # escapa comillas, barras, saltos de linea
        body = self.cfg.body_template.replace("{PROMPT}", safe)
        headers = {"Content-Type": "application/json", **(self.cfg.headers or {})}
        data = body.encode("utf-8")
        req = urllib.request.Request(
            self.cfg.url, data=data, headers=headers, method=self.cfg.method or "POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return TargetResponse("", raw, ok=False, error=f"HTTP {exc.code}", status=exc.code)
        except urllib.error.URLError as exc:
            return TargetResponse("", "", ok=False, error=str(exc.reason))

        text = raw
        if self.cfg.response_path:
            try:
                text = str(_dig(json.loads(raw), self.cfg.response_path))
            except (ValueError, KeyError, IndexError, TypeError):
                text = raw  # devuelve el crudo si la ruta no casa
        return TargetResponse(text=text, raw=raw, ok=True, status=status)


class CallableTarget(Target):
    """Envuelve un callable `modulo:funcion` que recibe str y devuelve str."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.name = cfg.name
        mod_name, _, func_name = cfg.callable.partition(":")
        if not func_name:
            raise TargetError(f"callable mal formado: '{cfg.callable}' (usa 'modulo:funcion')")
        module = importlib.import_module(mod_name)
        self._func = getattr(module, func_name)

    def send(self, prompt: str) -> TargetResponse:
        try:
            out = self._func(prompt)
        except Exception as exc:  # noqa: BLE001 - el bot puede lanzar cualquier cosa
            return TargetResponse("", "", ok=False, error=f"{type(exc).__name__}: {exc}")
        return TargetResponse(text=str(out), raw=str(out), ok=True)


def build_target(cfg) -> Target:
    if cfg.kind == "callable":
        return CallableTarget(cfg)
    return HttpTarget(cfg)
