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
    p.add_argument("engagement", nargs="*", help="Ruta(s) al JSON de engagement.")
    p.add_argument("-o", "--out", default="reports", help="Carpeta de salida (def: reports).")
    p.add_argument("--no-llm", action="store_true",
                   help="Fuerza modo gratis: sin atacante-LLM ni juez-LLM.")
    p.add_argument("--prefer", choices=["groq", "gemini"], default=None,
                   help="Proveedor LLM preferido si hay varias claves.")
    p.add_argument("--env", action="append", default=[],
                   help="Ruta(s) extra a ficheros .env con claves.")
    p.add_argument("--sarif", action="store_true",
                   help="Escribe tambien informe SARIF 2.1.0 (.sarif) para CI.")
    p.add_argument("--jobs", "-j", type=int, default=1,
                   help="Payloads en paralelo por objetivo (def: 1). Sube el ritmo "
                        "de peticiones; usalo con cuidado y solo si tienes permiso.")
    p.add_argument("--only-owasp", default="",
                   help="Filtra por codigos OWASP, coma-separados (p.ej. LLM01,LLM07).")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                   default=None, help="Lanza solo payloads de esta severidad o mayor.")
    p.add_argument("--fail-on", choices=["confirmed", "hits", "never"], default="confirmed",
                   help="Que hace devolver codigo de salida 1 (def: confirmed).")
    p.add_argument("--list-payloads", action="store_true",
                   help="Lista la libreria de payloads (segun --only-owasp/--min-severity) y sale.")
    p.add_argument("--serve", action="store_true",
                   help="Lanza el PANEL WEB local (interfaz visual) en vez de escanear por CLI.")
    p.add_argument("--host", default="127.0.0.1", help="Host del panel (def: 127.0.0.1).")
    p.add_argument("--port", type=int, default=8765, help="Puerto del panel (def: 8765).")
    p.add_argument("--version", action="version", version=f"PromptReaper {__version__}")
    return p


def _do_list_payloads(args) -> int:
    from .payloads import load_payloads
    only = {c.strip().upper() for c in args.only_owasp.split(",") if c.strip()} or None
    from .owasp import SEVERITY_ORDER
    payloads = load_payloads(["es", "en"])
    if only:
        payloads = [p for p in payloads if p.owasp.upper() in only]
    if args.min_severity:
        floor = SEVERITY_ORDER.get(args.min_severity, 0)
        payloads = [p for p in payloads if SEVERITY_ORDER.get(p.severity, 0) >= floor]
    print(f"{len(payloads)} payloads:\n")
    for p in sorted(payloads, key=lambda x: (x.owasp, x.lang, x.id)):
        print(f"  {p.id:14} {p.owasp}  {p.lang}  {p.severity:8} {p.goal:20} {p.technique}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    print(_BANNER)

    if args.list_payloads:
        return _do_list_payloads(args)

    if args.serve:
        # Carga de claves antes de levantar el panel (por si se usa LLM).
        for path in args.env + _default_env_paths():
            load_env_file(path)
        from .webpanel import serve
        serve(host=args.host, port=args.port, prefer=args.prefer, no_llm=args.no_llm)
        return 0

    if not args.engagement:
        print("Falta el fichero de engagement.\n"
              "Ejemplo:  python reaper.py engagements/lab.json\n"
              "Crea uno a partir de engagements/example-http.json", file=sys.stderr)
        return 2

    # Carga de claves (no pisa variables ya presentes).
    for path in args.env + _default_env_paths():
        load_env_file(path)

    only = [c.strip() for c in args.only_owasp.split(",") if c.strip()] or None
    os.makedirs(args.out, exist_ok=True)
    exit_code = 0
    aggregate = []

    for eng_path in args.engagement:
        try:
            eng = Engagement.from_file(eng_path)
        except (OSError, ValueError) as exc:
            print(f"No se pudo leer el engagement '{eng_path}': {exc}", file=sys.stderr)
            exit_code = max(exit_code, 2)
            continue

        # PUERTA DE CONSENTIMIENTO — control tecnico, no se puede saltar.
        try:
            eng.enforce_consent()
        except ConsentError as exc:
            print(f"\n[X] CONSENTIMIENTO NO VALIDO ({eng_path})\n" + str(exc), file=sys.stderr)
            exit_code = max(exit_code, 3)
            continue

        attacker_llm = judge_llm = None
        if not args.no_llm:
            if eng.use_llm_attacker:
                attacker_llm = get_llm(args.prefer)
            if eng.use_llm_judge:
                judge_llm = get_llm(args.prefer)

        print(f"Proyecto: {eng.project}  ·  objetivos: {len(eng.targets)}")
        print(f"Atacante: {attacker_llm.provider if attacker_llm else 'estatico (sin LLM)'}  ·  "
              f"Juez: {judge_llm.provider if judge_llm else 'heuristico (sin LLM)'}  ·  "
              f"jobs: {args.jobs}")
        print(f"Autorizacion: {eng.authorization_note}\n")

        scanner = Scanner(eng, attacker_llm=attacker_llm, judge_llm=judge_llm,
                          forbidden_markers=eng.forbidden_markers,
                          progress=lambda m: print("  " + m),
                          jobs=args.jobs, only_owasp=only, min_severity=args.min_severity)

        for tcfg in eng.targets:
            print(f"\n=== Escaneando: {tcfg.name} ===")
            report = scanner.scan_target(tcfg)
            grade, pts = report.score()
            base = os.path.join(args.out, _slug(f"{eng.project}_{tcfg.name}"))
            _write(base + ".json", report.to_json())
            _write(base + ".md", report.to_markdown())
            _write(base + ".html", report.to_html())
            if args.sarif:
                _write(base + ".sarif", report.to_sarif())
            print(f"\n  Nota: {grade} ({pts}/100)  ·  "
                  f"hits: {len(report.hits())}/{len(report.findings)} "
                  f"(confirmados: {len(report.confirmed())})")
            print(f"  Informe: {base}.md / .json / .html" + (" / .sarif" if args.sarif else ""))
            aggregate.append((eng.project, tcfg.name, grade, pts, report))
            if args.fail_on == "confirmed" and report.confirmed():
                exit_code = max(exit_code, 1)
            elif args.fail_on == "hits" and report.hits():
                exit_code = max(exit_code, 1)

    if len(aggregate) > 1:
        print("\n=== Resumen ===")
        for proj, name, grade, pts, rep in aggregate:
            print(f"  {proj}/{name}: {grade} ({pts}/100)  ·  confirmados: {len(rep.confirmed())}")
    return exit_code


def _slug(s: str) -> str:
    keep = "-_."
    return "".join(c if c.isalnum() or c in keep else "_" for c in s.lower())[:80]


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


if __name__ == "__main__":
    raise SystemExit(main())
