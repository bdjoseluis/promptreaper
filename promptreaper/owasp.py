"""Catálogo OWASP Top 10 for LLM Applications (edición 2025) usado por PromptReaper.

Solo incluimos las categorías que una auditoría *black-box* de un chatbot puede
observar desde fuera (sin acceso al servidor, al modelo ni al pipeline de datos).
Las categorías que requieren acceso interno (envenenamiento de datos de
entrenamiento, cadena de suministro del modelo, embeddings/vectores) quedan
documentadas pero marcadas como no comprobables en modo black-box.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OwaspCategory:
    code: str
    title_es: str
    title_en: str
    blackbox_testable: bool
    summary_es: str
    remediation_es: str = ""


# Fuente: OWASP Top 10 for LLM Applications 2025.
CATALOG: dict[str, OwaspCategory] = {
    "LLM01": OwaspCategory(
        code="LLM01",
        title_es="Inyección de prompt",
        title_en="Prompt Injection",
        blackbox_testable=True,
        summary_es=(
            "El atacante manipula la entrada para que el modelo ignore sus "
            "instrucciones originales y ejecute las del atacante (jailbreak, "
            "cambio de rol, saltos de guardarraíl)."
        ),
        remediation_es=(
            "Separar instrucciones de sistema y datos de usuario; validar/filtrar "
            "salidas; principio de mínimo privilegio en las herramientas; "
            "guardarraíles multilingües (no solo en inglés)."
        ),
    ),
    "LLM02": OwaspCategory(
        code="LLM02",
        title_es="Divulgación de información sensible",
        title_en="Sensitive Information Disclosure",
        blackbox_testable=True,
        summary_es=(
            "El modelo revela secretos, credenciales, PII o datos internos que "
            "estaban en su contexto, herramientas o system prompt."
        ),
        remediation_es=(
            "No colocar secretos ni PII en el system prompt ni en el contexto; "
            "saneado de salida; segmentación de datos; DLP sobre las respuestas."
        ),
    ),
    "LLM04": OwaspCategory(
        code="LLM04",
        title_es="Envenenamiento de datos/modelo",
        title_en="Data and Model Poisoning",
        blackbox_testable=False,
        summary_es="Requiere acceso al pipeline de entrenamiento; no comprobable en black-box.",
    ),
    "LLM05": OwaspCategory(
        code="LLM05",
        title_es="Manejo inadecuado de la salida",
        title_en="Improper Output Handling",
        blackbox_testable=True,
        summary_es=(
            "La salida del modelo se consume sin sanear y permite XSS, inyección "
            "SQL/comandos, SSRF o markdown/HTML peligroso aguas abajo."
        ),
        remediation_es=(
            "Tratar la salida del LLM como entrada no confiable: codificar/escapar, "
            "validar esquemas, CSP, sandbox de renderizado."
        ),
    ),
    "LLM06": OwaspCategory(
        code="LLM06",
        title_es="Agencia excesiva",
        title_en="Excessive Agency",
        blackbox_testable=True,
        summary_es=(
            "El bot dispone de herramientas/acciones con permisos amplios que un "
            "atacante puede inducir a usar (enviar correos, llamar APIs, etc.)."
        ),
        remediation_es=(
            "Mínimo privilegio en herramientas; aprobación humana para acciones "
            "sensibles; límites y auditoría de cada acción."
        ),
    ),
    "LLM07": OwaspCategory(
        code="LLM07",
        title_es="Fuga del system prompt",
        title_en="System Prompt Leakage",
        blackbox_testable=True,
        summary_es=(
            "El modelo revela su prompt de sistema, que puede contener reglas de "
            "negocio, secretos o pistas para saltarse sus propias defensas."
        ),
        remediation_es=(
            "No poner secretos en el system prompt; asumir que es descubrible; "
            "controles de seguridad fuera del prompt; detección de exfiltración."
        ),
    ),
    "LLM10": OwaspCategory(
        code="LLM10",
        title_es="Consumo ilimitado / abuso de recursos",
        title_en="Unbounded Consumption",
        blackbox_testable=True,
        summary_es=(
            "El bot puede usarse como proxy LLM gratuito para tareas ajenas a su "
            "propósito ('denial of wallet'): traducir, programar, resolver, etc., "
            "cargando el coste de tokens a la víctima."
        ),
        remediation_es=(
            "Limitar temática (system prompt + validación de salida), rate-limit "
            "por usuario/IP, cuotas y detección de abuso, longitud máxima."
        ),
    ),
}


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class CategoryResult:
    code: str
    findings: list = field(default_factory=list)

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER.get(s, 0))
