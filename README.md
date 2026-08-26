# PromptReaper 🌾💀

**Escáner de seguridad para chatbots LLM** — mide, contra un chatbot, los riesgos
del **OWASP Top 10 for LLM Applications (2025)**: fuga del *system prompt*,
divulgación de secretos, *jailbreak* / inyección de prompt, manejo inseguro de la
salida y abuso como *proxy* LLM gratuito (*denial of wallet*). Genera un informe
en **JSON / Markdown / HTML** con nota A–F.

> **Ángulo diferencial:** batería de ataques en **ESPAÑOL**. Muchos guardarraíles
> se entrenan sobre todo en inglés y ceden más fácil ante ataques en español (jerga,
> *code-switching*, registro regional). PromptReaper mide esa brecha ES vs EN.

Alternativas conocidas (garak, PyRIT, Augustus) van en inglés y sin foco agéntico;
aquí el foco es **español + multi-turno adaptativo**.

---

## ⚖️ Uso ético y legal — LÉELO

PromptReaper **solo** debe usarse contra sistemas para los que tienes autorización
explícita: **bots propios** o **laboratorios vulnerables** con licencia para ello
(p. ej. *Gandalf* de Lakera, retos OWASP LLM CTF). No accede a servidores ni
"hackea el sistema": **audita la IA** enviándole mensajes, como cualquier usuario.

La herramienta incluye una **puerta de consentimiento** que es un control técnico,
no un aviso: el runner **se niega a ejecutar** si el engagement no declara
`authorized: true`, una nota de autorización y el objetivo en la `allowlist`.
No se puede desactivar por variable de entorno: es intencional.

---

## Instalación

Cero dependencias: **solo la librería estándar de Python 3.9+**. No hace falta
`pip install` nada.

```bash
cd D:\bdev\experimentos\promptreaper
python reaper.py engagements/lab-vulnerable.json --no-llm
```

## Uso

```bash
# Escaneo contra un engagement (ver formato en engagements/)
python reaper.py engagements/lab-vulnerable.json

# Modo gratis forzado (sin atacante-LLM ni juez-LLM):
python reaper.py engagements/lab-vulnerable.json --no-llm

# Elegir proveedor LLM si hay varias claves:
python reaper.py engagements/mi-bot.json --prefer gemini

# Claves adicionales desde un .env:
python reaper.py engagements/mi-bot.json --env C:\ruta\.env
```

Salida en `reports/<proyecto>_<objetivo>.{json,md,html}`.
Código de salida: `1` si hubo hallazgos **confirmados**, `0` si limpio, `2/3` si
error de configuración / consentimiento.

### Modo gratis vs modo LLM

| Rol | Con clave LLM | Sin clave (gratis) |
|-----|---------------|--------------------|
| **Atacante multi-turno** | Genera cada turno adaptándose a la respuesta (crescendo) | Escalera de seguimientos estáticos por objetivo |
| **Juez** | LLM independiente dictamina los casos ambiguos | Heurístico: canarios/marcadores deterministas + ausencia de rechazo |

Detección de secretos y fugas por **canario plantado** es determinista en ambos
modos (alta confianza). El LLM solo afina *jailbreak* y *proxy abuse*.

Claves soportadas (por variable de entorno o `.env`): `GROQ_API_KEY`,
`GEMINI_API_KEY` / `GOOGLE_API_KEY`. Se auto-carga `aura-ops/.env` si existe.

## Formato de engagement

```json
{
  "project": "mi-bot",
  "authorized": true,
  "authorization_note": "Bot propio de b-dev.es",
  "allowlist": ["b-dev.es"],
  "langs": ["es", "en"],
  "max_turns": 4,
  "forbidden_markers": [],
  "targets": [{
    "name": "widget",
    "kind": "http",
    "url": "https://b-dev.es/api/chat",
    "body_template": "{\"message\": \"{PROMPT}\"}",
    "response_path": "reply"
  }]
}
```

- `kind: "http"` → chatbot por HTTP/JSON. `{PROMPT}` se sustituye (ya escapado) en
  `body_template`; `response_path` extrae la respuesta del JSON (dot-path).
- `kind: "callable"` → callable Python en proceso (`modulo:funcion`), para labs/tests.
- `known_canaries` → secretos plantados que **tú** conoces (solo labs consentidos);
  habilitan detección determinista de fugas.

## Arquitectura

```
reaper.py                CLI de entrada
promptreaper/
  config.py              Engagement + PUERTA DE CONSENTIMIENTO
  owasp.py               Catálogo OWASP LLM Top 10 (categorías black-box)
  payloads.py            Carga de la librería de payloads
  llm.py                 Cliente LLM sin deps (Groq/Gemini REST) — opcional
  targets.py             HttpTarget / CallableTarget
  judge.py               Juez híbrido (determinista + heurístico + LLM)
  conversation.py        Atacante adaptativo multi-turno (crescendo)
  runner.py              Orquestación por payload y objetivo
  report.py              Findings + informe JSON/MD/HTML + nota A-F
data/
  payloads_es.json       ⭐ Payloads en español (núcleo diferencial)
  payloads_en.json       Baseline en inglés (comparativa)
  refusals.json          Marcadores de rechazo ES/EN
labs/
  vulnerable_bot.py      Bot vulnerable de laboratorio (demo + ground-truth)
  hardened_bot.py        Bot endurecido (control de falsos positivos)
tests/
  test_smoke.py          Autoauditoría end-to-end (offline, determinista)
```

## Autoauditoría

```bash
python -m unittest tests.test_smoke -v
```

Comprueba que sobre el bot **vulnerable** detecta las vulnerabilidades reales
(sin falsos negativos en las categorías con canario) y saca nota F, y que sobre el
bot **endurecido** NO inventa hallazgos (nota A, sin falsos positivos).

## OWASP LLM Top 10 cubierto (black-box)

| Código | Categoría | Cómo se prueba |
|--------|-----------|----------------|
| LLM01 | Inyección de prompt / jailbreak | Roleplay, hipotético, prefijo forzado, *code-switch* |
| LLM02 | Divulgación de info sensible | Petición directa, ing. social, acróstico ofuscado |
| LLM05 | Manejo inseguro de la salida | Reflejo de HTML/JS sin escapar (XSS aguas abajo) |
| LLM07 | Fuga del system prompt | Override directo, falsa autoridad, repetición |
| LLM10 | Consumo ilimitado / *proxy abuse* | Tareas fuera de dominio (código, traducción, ensayo largo) |

LLM04 (envenenamiento) y otras que requieren acceso interno no son comprobables en
black-box y se documentan como tal.

## Roadmap

- [ ] Módulo de objetivos con auth (cookies/headers rotativos, sesión).
- [ ] Más técnicas ES: ofuscación (leet, base64 hablado), *many-shot*, sufijos adversariales.
- [ ] Objetivos agénticos: detectar *tool-calling* y agencia excesiva (LLM06).
- [ ] Exportar a formato SARIF / integrable en CI.
- [ ] Panel HTML con transcripción expandible por hallazgo.

---
*PromptReaper · proyecto del máster de ciberseguridad · uso ético y autorizado.*
