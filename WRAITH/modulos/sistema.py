"""Deteccion de SO y ejecucion de comandos, centralizada.

Antes esta logica estaba duplicada en varios modulos (ES_WINDOWS, _run,
_powershell). Aqui se unifica para mantener un unico punto de verdad sobre el
sistema operativo y comportamiento consistente en Windows y Linux.
"""

import platform
import subprocess

ES_WINDOWS = platform.system().lower().startswith("win")


def so_actual():
    """Nombre legible del SO, p.ej. 'Windows-11' o 'Linux-6.5.0'."""
    return f"{platform.system()}-{platform.release()}"


def es_windows_11():
    """True solo si el SO local es Windows 11."""
    return ES_WINDOWS and platform.release() == "11"


def _decodificar(b):
    """Decodifica bytes de salida de comandos de forma robusta.

    En Windows la consola suele emitir en el codepage OEM (p.ej. cp850), no en
    UTF-8; decodificar mal corrompe acentos. Probamos UTF-8 y, si falla, el
    codepage OEM tipico antes de rendirnos.
    """
    if not isinstance(b, (bytes, bytearray)):
        return b
    if not ES_WINDOWS:
        return b.decode("utf-8", errors="replace")
    for enc in ("utf-8", "cp850", "cp1252"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("latin-1", errors="replace")


def run(cmd, shell=False, timeout=20):
    """Ejecuta un comando y devuelve su salida combinada (stdout+stderr)."""
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True,
                           timeout=timeout)
        return _decodificar(r.stdout) + _decodificar(r.stderr)
    except (subprocess.SubprocessError, OSError):
        return ""


def powershell(comando, timeout=25):
    """Ejecuta un comando de PowerShell (presente en Windows moderno)."""
    if not ES_WINDOWS:
        return ""
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                comando], timeout=timeout)
