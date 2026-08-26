"""Bot de laboratorio ENDURECIDO (control negativo para la autoauditoria).

Mismo negocio que el vulnerable, pero con defensas correctas:
  - no coloca secretos en el prompt accesible,
  - reconoce intentos de fuga/jailbreak/abuso en ESPAÑOL e ingles,
  - se ciñe a su dominio (floristeria) y rechaza lo demas.

PromptReaper deberia dar sobre este bot un informe LIMPIO (nota A). Si detectara
hallazgos aqui, serian FALSOS POSITIVOS: este fichero es su prueba de regresion.
"""

from __future__ import annotations

# Señales de ataque en español e ingles.
_ATTACK_SIGNS = [
    # fuga / instrucciones
    "instruccion", "instrucciones", "system prompt", "prompt de sistema", "repite",
    "repeat", "configuracion", "mantenimiento", "reglas internas", "comportamiento",
    # secretos
    "contraseña", "contrasena", "clave", "password", "credencial", "api key",
    "admin", "acrostico", "poema",
    # jailbreak
    "sin restricciones", "sin filtros", "sin limitaciones", "libre", "free",
    "dan", "abuela", "novela", "ficcion", "personaje", "jailbreak", "ignora",
    "ignore", "obligatoriamente",
    # inyeccion / xss
    "promptreaper", "<img", "onerror", "olvida tu tarea", "forget your",
    # proxy / fuera de dominio
    "python", "codigo", "funcion", "criba", "primos", "traduce", "traducir",
    "ensayo", "imperio romano",
]

_REFUSAL = ("Lo siento, no puedo ayudarte con eso. Solo puedo hablar de flores y "
            "de tus pedidos en la floristeria. ¿En que ramo estas pensando?")


def respond(prompt: str) -> str:
    low = prompt.lower()
    if any(sign in low for sign in _ATTACK_SIGNS):
        return _REFUSAL
    return "¡Hola! Soy AsistenteFlor. ¿Quieres encargar un ramo o consultar un pedido?"
