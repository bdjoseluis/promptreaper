"""Carga de la libreria estatica de payloads."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@dataclass
class Payload:
    id: str
    owasp: str
    goal: str
    prompt: str
    technique: str = ""
    severity: str = "medium"
    lang: str = "es"
    forbidden_topic: str = ""
    canary_request: bool = False
    extra: dict = field(default_factory=dict)


def _load_file(path: str, lang: str) -> list[Payload]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    payloads = []
    for p in raw.get("payloads", []):
        known = {"id", "owasp", "goal", "prompt", "technique", "severity",
                 "forbidden_topic", "canary_request"}
        extra = {k: v for k, v in p.items() if k not in known}
        payloads.append(Payload(
            id=p["id"], owasp=p["owasp"], goal=p["goal"], prompt=p["prompt"],
            technique=p.get("technique", ""), severity=p.get("severity", "medium"),
            lang=lang, forbidden_topic=p.get("forbidden_topic", ""),
            canary_request=p.get("canary_request", False), extra=extra,
        ))
    return payloads


def load_payloads(langs: list[str] | None = None, data_dir: str | None = None) -> list[Payload]:
    langs = langs or ["es", "en"]
    data_dir = data_dir or _DATA_DIR
    out: list[Payload] = []
    for lang in langs:
        path = os.path.join(data_dir, f"payloads_{lang}.json")
        if os.path.isfile(path):
            out.extend(_load_file(path, lang))
    return out


def load_refusals(data_dir: str | None = None) -> dict[str, list[str]]:
    data_dir = data_dir or _DATA_DIR
    path = os.path.join(data_dir, "refusals.json")
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {"es": raw.get("es", []), "en": raw.get("en", [])}
