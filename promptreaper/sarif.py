"""Exportacion a SARIF 2.1.0 para integracion en CI (GitHub code scanning, etc.).

Cada categoria OWASP LLM se mapea a una `rule` y cada hallazgo con exito a un
`result`. La severidad OWASP se traduce a `level` SARIF (error/warning/note) y a
`security-severity` (0-10) que GitHub usa para ordenar alertas.
"""

from __future__ import annotations

import json

from .owasp import CATALOG

_LEVEL = {  # OWASP severity -> SARIF level
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}
_SECURITY_SEVERITY = {  # OWASP severity -> GitHub security-severity (0-10)
    "critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0",
}
_TOOL_URI = "https://github.com/bdjoseluis/promptreaper"


def _rules() -> list[dict]:
    rules = []
    for code, cat in CATALOG.items():
        rules.append({
            "id": code,
            "name": cat.title_en.replace(" ", ""),
            "shortDescription": {"text": f"{code} {cat.title_en}"},
            "fullDescription": {"text": cat.summary_es},
            "helpUri": "https://genai.owasp.org/llm-top-10/",
            "help": {"text": cat.remediation_es or cat.summary_es},
            "properties": {"tags": ["security", "owasp-llm", code],
                           "blackbox-testable": cat.blackbox_testable},
        })
    return rules


def to_sarif(report) -> str:
    """Serializa un Report al esquema SARIF 2.1.0 (solo hallazgos con exito)."""
    results = []
    for f in report.hits():
        cat = CATALOG.get(f.owasp)
        title = cat.title_es if cat else f.owasp
        results.append({
            "ruleId": f.owasp,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": (
                f"[{f.status}] {title} · payload {f.payload_id} ({f.lang}, "
                f"{f.technique}): {f.reason}"
            )},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"target/{report.target_name}"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": report.target_name, "kind": "target"}],
            }],
            "partialFingerprints": {"promptreaper/v1": f"{report.target_name}:{f.payload_id}"},
            "properties": {
                "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.5"),
                "confidence": round(f.confidence, 2),
                "method": f.method,
                "status": f.status,
                "lang": f.lang,
                "turns_used": f.turns_used,
            },
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PromptReaper",
                "informationUri": _TOOL_URI,
                "rules": _rules(),
            }},
            "results": results,
            "properties": {
                "project": report.project,
                "target": report.target_name,
                "grade": report.score()[0],
                "points": report.score()[1],
            },
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
