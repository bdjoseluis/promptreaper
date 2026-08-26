"""Interfaz de linea de comandos de PromptReaper."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .config import Engagement, ConsentError, load_env_file
from .llm import get_llm
from .runner import Scanner

_BANNER = r"""
  ____                      _   ____
 |  _ \ _ __ ___  _ __ ___ | |_|  _ \ ___  __ _ _ __   ___ _ __
 | |_) | '__/ _ \| '_ ` _ \| __| |_) / _ \/ _` | '_ \ / _ \ '__|
 |  __/| | | (_) | | | | | | |_|  _ <  __/ (_| | |_) |  __/ |
 |_|   |_|  \___/|_| |_| |_|\__|_| \_\___|\__,_| .__/ \___|_|
   escaner de seguridad para chatbots LLM       |_|  OWASP LLM Top 10
"""


def _default_env_paths() -> list[str]:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [
        os.path.join(here, ".env"),
        r"D:\bdev\experimentos\aura-ops\.env",
    ]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="promptreaper",
        description="Escaner de seguridad de chatbots LLM (OWASP LLM Top 10). "
                    "Uso etico y autorizado unicamente.",
    )
    p.add_argument("engagement", nargs="?", help="Ruta al JSON de engagement.")
    p.add_argument("-o", "--out", default="reports", help="Carpeta de salida (def: reports).")
    p.add_argument("--no-llm", action="store_true",
                   help="Fuerza modo gratis: sin atacante-LLM ni juez-LLM.")
    p.add_argument("--prefer", choices=["groq", "gemini"], default=None,
                   help="Proveedor LLM preferido si hay varias claves.")
    p.add_argument("--env", action="append", default=[],
                   help="Ruta(s) extra a ficheros .env con claves.")
    p.add_argument("--version", action="version", version=f"PromptReaper {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    print(_BANNER)

    if not args.engagement:
        print("Falta el fichero de engagement.\n"
              "Ejemplo:  python reaper.py engagements/lab.json\n"
              "Crea uno a partir de engagements/example.json", file=sys.stderr)
        return 2

    # Carga de claves (no pisa variables ya presentes).
    for path in args.env + _default_env_paths():
        load_env_file(path)

    try:
        eng = Engagement.from_file(args.engagement)
    except (OSError, ValueError) as exc:
        print(f"No se pudo leer el engagement: {exc}", file=sys.stderr)
        return 2

    # PUERTA DE CONSENTIMIENTO — control tecnico, no se puede saltar.
    try:
        eng.enforce_consent()
    except ConsentError as exc:
        print("\n[X] CONSENTIMIENTO NO VALIDO\n" + str(exc), file=sys.stderr)
        return 3

    attacker_llm = judge_llm = None
    if not args.no_llm:
        if eng.use_llm_attacker:
            attacker_llm = get_llm(args.prefer)
        if eng.use_llm_judge:
            judge_llm = get_llm(args.prefer)

    print(f"Proyecto: {eng.project}  ·  objetivos: {len(eng.targets)}")
    print(f"Atacante: {attacker_llm.provider if attacker_llm else 'estatico (sin LLM)'}  ·  "
          f"Juez: {judge_llm.provider if judge_llm else 'heuristico (sin LLM)'}")
    print(f"Autorizacion: {eng.authorization_note}\n")

    scanner = Scanner(eng, attacker_llm=attacker_llm, judge_llm=judge_llm,
                      forbidden_markers=eng.forbidden_markers,
                      progress=lambda m: print("  " + m))

    os.makedirs(args.out, exist_ok=True)
    exit_code = 0
    for tcfg in eng.targets:
        print(f"\n=== Escaneando: {tcfg.name} ===")
        report = scanner.scan_target(tcfg)
        grade, pts = report.score()
        base = os.path.join(args.out, _slug(f"{eng.project}_{tcfg.name}"))
        _write(base + ".json", report.to_json())
        _write(base + ".md", report.to_markdown())
        _write(base + ".html", report.to_html())
        print(f"\n  Nota: {grade} ({pts}/100)  ·  "
              f"hits: {len(report.hits())}/{len(report.findings)} "
              f"(confirmados: {len(report.confirmed())})")
        print(f"  Informe: {base}.md / .json / .html")
        if report.confirmed():
            exit_code = 1  # hubo hallazgos confirmados
    return exit_code


def _slug(s: str) -> str:
    keep = "-_."
    return "".join(c if c.isalnum() or c in keep else "_" for c in s.lower())[:80]


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


if __name__ == "__main__":
    raise SystemExit(main())
