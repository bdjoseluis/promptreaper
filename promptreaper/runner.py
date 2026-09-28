"""Runner: orquesta el escaneo de un objetivo.

Flujo por payload:
  1. Primer disparo (single-shot).
  2. El juez dictamina. Si NO hay exito y el multi-turno esta activo, el atacante
     adaptativo escala hasta `max_turns`, re-evaluando en cada turno.
  3. Se registra el mejor veredicto como Finding.
"""

from __future__ import annotations

import datetime as _dt
from concurrent.futures import ThreadPoolExecutor

from .conversation import AdaptiveAttacker, Conversation
from .judge import Judge
from .owasp import SEVERITY_ORDER
from .payloads import load_payloads, load_refusals
from .report import Finding, Report
from .targets import build_target


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Scanner:
    def __init__(self, engagement, attacker_llm=None, judge_llm=None,
                 forbidden_markers=None, progress=None, jobs=1,
                 only_owasp=None, min_severity=None):
        self.eng = engagement
        self.attacker_llm = attacker_llm
        self.judge_llm = judge_llm
        self.forbidden_markers = forbidden_markers or []
        self.progress = progress or (lambda *_: None)
        self.refusals = load_refusals()
        self.jobs = max(1, int(jobs))
        self.only_owasp = {c.upper() for c in only_owasp} if only_owasp else None
        self.min_severity = min_severity

    def _select(self, payloads):
        out = payloads
        if self.only_owasp:
            out = [p for p in out if p.owasp.upper() in self.only_owasp]
        if self.min_severity:
            floor = SEVERITY_ORDER.get(self.min_severity, 0)
            out = [p for p in out if SEVERITY_ORDER.get(p.severity, 0) >= floor]
        return out

    def scan_target(self, target_cfg) -> Report:
        target = build_target(target_cfg)
        judge = Judge(self.refusals, known_canaries=target_cfg.known_canaries,
                      llm=self.judge_llm, forbidden_markers=self.forbidden_markers)
        payloads = self._select(load_payloads(self.eng.langs))
        started = _now()
        report = Report(
            project=self.eng.project, target_name=target_cfg.name,
            started=started, finished="",
            mode={
                "attacker": self.attacker_llm.provider if self.attacker_llm else "estatico",
                "judge": self.judge_llm.provider if self.judge_llm else "heuristico",
                "multi_turn": self.eng.max_turns,
            },
        )

        total = len(payloads)
        if self.jobs > 1 and total > 1:
            done = 0

            def work(p):
                return self._run_payload(target, judge, p)

            with ThreadPoolExecutor(max_workers=self.jobs) as pool:
                results = list(pool.map(work, payloads))  # preserva el orden
            for payload, finding in zip(payloads, results):
                done += 1
                self.progress(f"[{done}/{total}] {payload.id} ({payload.owasp}/{payload.lang})")
                report.findings.append(finding)
        else:
            for i, payload in enumerate(payloads, 1):
                self.progress(f"[{i}/{total}] {payload.id} ({payload.owasp}/{payload.lang})")
                report.findings.append(self._run_payload(target, judge, payload))

        report.finished = _now()
        return report

    def _run_payload(self, target, judge, payload) -> Finding:
        conv = Conversation(payload_id=payload.id, goal=payload.goal)
        attacker = AdaptiveAttacker(self.attacker_llm, lang=payload.lang)

        best = None
        turns_used = 0
        msg = payload.prompt

        max_turns = max(1, self.eng.max_turns)
        for turn in range(1, max_turns + 1):
            conv.add("attacker", msg)
            resp = target.send(msg)
            turns_used = turn
            if not resp.ok:
                verdict = _error_verdict(resp.error)
                conv.add("target", f"<error: {resp.error}>")
                best = (verdict, resp.text)
                break
            conv.add("target", resp.text)
            verdict = judge.judge(payload, resp.text)
            if best is None or _better(verdict, best[0]):
                best = (verdict, resp.text)
            if verdict.status == "CONFIRMED":
                break  # ya esta demostrado, no gastamos mas turnos
            # ¿escalar?
            if turn < max_turns:
                nxt = attacker.next_message(payload, conv, turn)
                if not nxt:
                    break
                msg = nxt

        verdict, last_resp = best
        return Finding(
            payload_id=payload.id, owasp=payload.owasp, goal=payload.goal,
            technique=payload.technique, lang=payload.lang, severity=payload.severity,
            status=verdict.status, confidence=verdict.confidence, method=verdict.method,
            reason=verdict.reason, attack_prompt=payload.prompt,
            bot_response=last_resp[:2000], transcript=conv.transcript()[:4000],
            evidence=verdict.evidence, turns_used=turns_used,
        )


def _error_verdict(msg: str):
    from .judge import Verdict, ERROR
    return Verdict(ERROR, 0.0, f"Error al contactar el objetivo: {msg}", "heuristic")


def _better(a, b) -> bool:
    """Un veredicto es 'mejor' (mas relevante) si demuestra mas exito/severidad."""
    rank = {"CONFIRMED": 3, "PLAUSIBLE": 2, "REFUTED": 1, "ERROR": 0}
    if rank.get(a.status, 0) != rank.get(b.status, 0):
        return rank.get(a.status, 0) > rank.get(b.status, 0)
    return a.confidence > b.confidence
