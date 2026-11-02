"""Auditor de robustez de contrasenas y politica (alternativa defensiva a John).

NO craquea hashes ni ataca credenciales ajenas. Evalua la fortaleza de una
contrasena que el propio usuario escribe (para aprender a elegir buenas) y
revisa la politica de cuentas del sistema local.
"""

import math
import re

from modulos import sistema

# Lista corta de contrasenas muy comunes (muestra; ampliable).
COMUNES = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "dragon", "football", "iloveyou", "sunshine", "princess", "qwerty123",
    "000000", "password1", "root", "toor", "changeme", "p@ssw0rd", "contrasena",
}


def _entropia_bits(texto):
    """Estima bits de entropia a partir del tamano del alfabeto usado."""
    if not texto:
        return 0.0
    alfabeto = 0
    if re.search(r"[a-z]", texto):
        alfabeto += 26
    if re.search(r"[A-Z]", texto):
        alfabeto += 26
    if re.search(r"\d", texto):
        alfabeto += 10
    if re.search(r"[^\w]", texto):
        alfabeto += 33
    return len(texto) * math.log2(alfabeto) if alfabeto else 0.0


def evaluar_password(texto):
    """Evalua una contrasena. Devuelve dict con puntuacion y consejos.

    No almacena ni transmite la contrasena; solo calcula metricas locales.
    """
    consejos = []
    bits = _entropia_bits(texto)

    if texto.lower() in COMUNES:
        consejos.append("Esta en listas de contrasenas comunes: cambiala ya.")
    if len(texto) < 12:
        consejos.append("Usa 12+ caracteres (idealmente 16+).")
    if not re.search(r"[a-z]", texto):
        consejos.append("Agrega minusculas.")
    if not re.search(r"[A-Z]", texto):
        consejos.append("Agrega mayusculas.")
    if not re.search(r"\d", texto):
        consejos.append("Agrega numeros.")
    if not re.search(r"[^\w]", texto):
        consejos.append("Agrega simbolos.")
    if re.search(r"(.)\1\1", texto):
        consejos.append("Evita caracteres repetidos (aaa, 111).")
    if re.search(r"(?:0123|1234|2345|abcd|qwer)", texto.lower()):
        consejos.append("Evita secuencias (1234, qwerty, abcd).")

    if texto.lower() in COMUNES or bits < 28:
        nivel = "Muy debil"
    elif bits < 40:
        nivel = "Debil"
    elif bits < 60:
        nivel = "Aceptable"
    elif bits < 80:
        nivel = "Fuerte"
    else:
        nivel = "Muy fuerte"

    return {
        "nivel": nivel,
        "bits": round(bits, 1),
        "longitud": len(texto),
        "consejos": consejos or ["Buena contrasena. Usa un gestor y 2FA."],
    }


def auditar_politica_local():
    """Lee la politica de cuentas del SO. Devuelve lista de lineas informativas."""
    lineas = []
    if sistema.ES_WINDOWS:
        out = sistema.run(["net", "accounts"])
        for linea in out.splitlines():
            if ":" in linea and linea.strip():
                lineas.append(linea.strip())
    else:
        try:
            with open("/etc/login.defs", "r", errors="replace") as f:
                for linea in f:
                    l = linea.strip()
                    if l and not l.startswith("#") and l.split()[0] in (
                        "PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN",
                        "PASS_WARN_AGE",
                    ):
                        lineas.append(l)
        except OSError:
            pass
    return lineas or ["No se pudo leer la politica de cuentas local."]
