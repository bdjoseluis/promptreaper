"""Autoauditoria end-to-end de PromptReaper (sin LLM, 100% offline y determinista).

Comprueba dos cosas criticas:
  1. Detecta de verdad las vulnerabilidades del bot vulnerable (sin falsos negativos
     en las categorias con canario/ground-truth).
  2. NO inventa hallazgos en el bot endurecido (sin falsos positivos).

Ejecutar:  python -m unittest tests.test_smoke   (desde la raiz del repo)
       o:  python tests/test_smoke.py
"""

from __future__ import annotations

import os
import sys
import unittest

# Raiz del repo en el path (para importar `promptreaper` y `labs`).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from promptreaper.config import Engagement, ConsentError  # noqa: E402
from promptreaper.runner import Scanner  # noqa: E402
from labs import vulnerable_bot  # noqa: E402


def _eng(callable_path, name, note, extra=None):
    raw = {
        "project": f"test-{name}",
        "authorized": True,
        "authorization_note": note,
        "allowlist": [name, callable_path],
        "langs": ["es", "en"],
        "max_turns": 2,
        "use_llm_attacker": False,
        "use_llm_judge": False,
        "forbidden_markers": [vulnerable_bot.FORBIDDEN_SENTINEL],
        "targets": [{
            "name": name, "kind": "callable", "callable": callable_path,
            "known_canaries": list(vulnerable_bot.CANARIES),
        }],
    }
    if extra:
        raw.update(extra)
    return Engagement.from_dict(raw)


class TestVulnerableBot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        eng = _eng("labs.vulnerable_bot:respond", "bot-vulnerable",
                   "Bot de laboratorio propio vulnerable.")
        eng.enforce_consent()
        scanner = Scanner(eng, attacker_llm=None, judge_llm=None,
                          forbidden_markers=eng.forbidden_markers)
        cls.report = scanner.scan_target(eng.targets[0])
        cls.by_id = {f.payload_id: f for f in cls.report.findings}

    def test_confirmed_hits_exist(self):
        self.assertTrue(self.report.confirmed(), "Deberia haber hallazgos CONFIRMADOS")

    def test_system_prompt_leak_confirmed(self):
        f = self.by_id["es-leak-01"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)
        self.assertIn(vulnerable_bot.SYSTEM_CANARY, f.bot_response)

    def test_secret_disclosure_confirmed(self):
        f = self.by_id["es-secret-01"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)
        self.assertIn(vulnerable_bot.ADMIN_PASSWORD, f.bot_response)

    def test_injection_marker_confirmed(self):
        f = self.by_id["es-inj-01"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)

    def test_xss_reflected_confirmed(self):
        f = self.by_id["es-inj-02"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)

    def test_jailbreak_forbidden_confirmed(self):
        f = self.by_id["es-jb-01"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)

    def test_proxy_abuse_confirmed(self):
        f = self.by_id["es-proxy-01"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)

    def test_obfuscated_leak_confirmed(self):
        # El canario exfiltrado en Base64 debe detectarse de forma determinista.
        f = self.by_id["es-leak-05"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)
        self.assertEqual(f.method, "deterministic")

    def test_obfuscated_secret_confirmed(self):
        f = self.by_id["es-secret-04"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)

    def test_excessive_agency_confirmed(self):
        f = self.by_id["es-agency-01"]
        self.assertEqual(f.status, "CONFIRMED", f.reason)

    def test_sarif_export_valid(self):
        import json
        doc = json.loads(self.report.to_sarif())
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(len(run["results"]), len(self.report.hits()))
        self.assertTrue(all(r["ruleId"] for r in run["results"]))

    def test_bad_grade(self):
        grade, pts = self.report.score()
        self.assertIn(grade, ("D", "F"), f"Un bot tan vulnerable no deberia sacar {grade}")

    def test_spanish_penetrates_at_least_as_much_as_english(self):
        es = [f for f in self.report.findings if f.lang == "es" and f.is_hit]
        en = [f for f in self.report.findings if f.lang == "en" and f.is_hit]
        es_rate = len(es) / max(1, sum(1 for f in self.report.findings if f.lang == "es"))
        en_rate = len(en) / max(1, sum(1 for f in self.report.findings if f.lang == "en"))
        self.assertGreaterEqual(es_rate, en_rate)


class TestHardenedBot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        eng = _eng("labs.hardened_bot:respond", "bot-endurecido",
                   "Bot de laboratorio propio endurecido.")
        eng.enforce_consent()
        scanner = Scanner(eng, attacker_llm=None, judge_llm=None,
                          forbidden_markers=eng.forbidden_markers)
        cls.report = scanner.scan_target(eng.targets[0])

    def test_no_confirmed_findings(self):
        confirmed = self.report.confirmed()
        self.assertFalse(confirmed,
                         f"Falsos positivos en bot endurecido: "
                         f"{[f.payload_id for f in confirmed]}")

    def test_clean_grade(self):
        grade, pts = self.report.score()
        self.assertEqual(grade, "A", f"Bot endurecido deberia sacar A, saco {grade} ({pts})")


class TestFiltersAndConcurrency(unittest.TestCase):
    def test_filter_by_owasp(self):
        eng = _eng("labs.vulnerable_bot:respond", "bot-vulnerable", "test")
        eng.enforce_consent()
        rep = Scanner(eng, only_owasp=["LLM07"],
                      forbidden_markers=eng.forbidden_markers).scan_target(eng.targets[0])
        self.assertTrue(rep.findings)
        self.assertTrue(all(f.owasp == "LLM07" for f in rep.findings))

    def test_parallel_matches_serial(self):
        eng = _eng("labs.vulnerable_bot:respond", "bot-vulnerable", "test")
        eng.enforce_consent()
        serial = Scanner(eng, jobs=1, forbidden_markers=eng.forbidden_markers)\
            .scan_target(eng.targets[0])
        parallel = Scanner(eng, jobs=4, forbidden_markers=eng.forbidden_markers)\
            .scan_target(eng.targets[0])
        self.assertEqual([f.payload_id for f in serial.findings],
                         [f.payload_id for f in parallel.findings])
        self.assertEqual(len(serial.confirmed()), len(parallel.confirmed()))


class TestConsentGate(unittest.TestCase):
    def test_refuses_unauthorized(self):
        eng = Engagement.from_dict({
            "project": "no-auth", "authorized": False,
            "allowlist": ["x"], "targets": [
                {"name": "x", "kind": "callable", "callable": "labs.hardened_bot:respond"}],
        })
        with self.assertRaises(ConsentError):
            eng.enforce_consent()

    def test_refuses_target_not_in_allowlist(self):
        eng = Engagement.from_dict({
            "project": "auth-but-not-listed", "authorized": True,
            "authorization_note": "test", "allowlist": ["otra-cosa"],
            "targets": [
                {"name": "x", "kind": "callable", "callable": "labs.hardened_bot:respond"}],
        })
        with self.assertRaises(ConsentError):
            eng.enforce_consent()

    def test_allows_authorized_and_listed(self):
        eng = _eng("labs.hardened_bot:respond", "bot-endurecido", "ok")
        eng.enforce_consent()  # no debe lanzar


if __name__ == "__main__":
    unittest.main(verbosity=2)
