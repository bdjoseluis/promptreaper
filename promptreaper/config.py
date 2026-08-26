"""Configuracion de engagement y PUERTA DE CONSENTIMIENTO.

PromptReaper solo debe usarse contra sistemas para los que se tiene autorizacion
explicita. Esta puerta es un control tecnico (no solo documental): el runner se
niega a lanzar ataques si el engagement no declara `authorized: true` y el
objetivo no aparece en la allowlist.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ConsentError(Exception):
    """Se lanza cuando falta autorizacion o el objetivo no esta en la allowlist."""


@dataclass
class TargetConfig:
    name: str
    kind: str = "http"            # "http" | "callable"
    url: str = ""
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    # Plantilla del cuerpo. El texto del ataque sustituye a "{PROMPT}".
    body_template: str = '{"message": "{PROMPT}"}'
    # Ruta (dot-path) para extraer la respuesta del JSON devuelto. Vacio = texto plano.
    response_path: str = ""
    timeout: int = 30
    # Callable "modulo:funcion" para objetivos en proceso (labs/tests).
    callable: str = ""
    # Secretos/canarios PLANTADOS que este objetivo conoce (solo labs consentidos).
    # Permiten deteccion determinista de fugas. Nunca poner secretos reales de terceros.
    known_canaries: list = field(default_factory=list)


@dataclass
class Engagement:
    """Un engagement autorizado contra uno o varios objetivos."""

    project: str = "sin-nombre"
    operator: str = ""
    authorized: bool = False
    authorization_note: str = ""      # p.ej. "Bot propio de b-dev.es" / "Lab Gandalf"
    allowlist: list = field(default_factory=list)  # nombres o hosts permitidos
    targets: list = field(default_factory=list)     # list[TargetConfig]
    langs: list = field(default_factory=lambda: ["es", "en"])
    max_turns: int = 4                # turnos del atacante adaptativo multi-turno
    use_llm_attacker: bool = True     # usa LLM si hay clave; si no, degrada a estatico
    use_llm_judge: bool = True
    # Marcadores de "contenido prohibido" que el juez trata como jailbreak
    # CONFIRMADO si aparecen en la salida (solo labs con salida controlada).
    forbidden_markers: list = field(default_factory=list)

    @staticmethod
    def from_file(path: str) -> "Engagement":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return Engagement.from_dict(raw)

    @staticmethod
    def from_dict(raw: dict) -> "Engagement":
        targets = [TargetConfig(**t) for t in raw.get("targets", [])]
        known = set(Engagement.__dataclass_fields__)
        kwargs = {k: v for k, v in raw.items() if k in known and k != "targets"}
        return Engagement(targets=targets, **kwargs)

    def enforce_consent(self) -> None:
        """Control tecnico: aborta si no hay autorizacion valida.

        Lanza ConsentError con un mensaje accionable. NO se puede desactivar por
        variable de entorno: es intencional.
        """
        if not self.authorized:
            raise ConsentError(
                "Engagement no autorizado. Anade \"authorized\": true y una "
                "\"authorization_note\" que describa por que tienes permiso "
                "(bot propio, lab vulnerable con licencia, etc.). PromptReaper "
                "solo audita sistemas consentidos."
            )
        if not self.authorization_note.strip():
            raise ConsentError(
                "Falta \"authorization_note\": describe la base de tu autorizacion."
            )
        if not self.targets:
            raise ConsentError("El engagement no tiene objetivos definidos.")
        allow = {a.lower() for a in self.allowlist}
        for t in self.targets:
            if not self._target_allowed(t, allow):
                raise ConsentError(
                    f"El objetivo '{t.name}' ({t.url or t.callable}) no esta en la "
                    f"allowlist {sorted(allow)}. Anade su nombre o host a "
                    f"\"allowlist\" para confirmar explicitamente el consentimiento."
                )

    @staticmethod
    def _target_allowed(t: TargetConfig, allow: set[str]) -> bool:
        if not allow:
            return False
        if t.name.lower() in allow:
            return True
        if t.kind == "callable":
            # Para labs en proceso basta con el nombre en la allowlist.
            return t.callable.lower() in allow
        host = urlparse(t.url).hostname or ""
        host = host.lower()
        if host in allow:
            return True
        # Permite comodin por sufijo de dominio: "b-dev.es" cubre "www.b-dev.es".
        return any(host == a or host.endswith("." + a) for a in allow)


def load_env_file(path: str) -> None:
    """Carga variables KEY=VALUE de un .env al entorno si no estan ya definidas.

    Best-effort: ignora comentarios y lineas vacias. No pisa variables existentes.
    """
    if not path or not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
