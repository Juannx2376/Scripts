"""Auditoria de hashes por diccionario / fuerza bruta (estilo John the Ripper).

Herramienta de auditoria de contrasenas: dado un hash que el usuario YA POSEE
(de su propia maquina o de una box de CTF donde esta autorizado), intenta
encontrar la contrasena en claro para detectar credenciales debiles.

Solo biblioteca estandar. NO vuelca hashes de SAM/shadow: el usuario aporta los
hashes (pegados o en un archivo). Pensado para auditoria / CTF / educacion.
"""

import hashlib
import itertools
import string

from modulos import password_audit

try:
    import crypt as _crypt  # solo Linux; para $1$/$5$/$6$
except Exception:
    _crypt = None


# --------------------------------------------------------------------------- #
#  MD4 puro (para NTLM; hashlib suele no traerlo con OpenSSL 3)
# --------------------------------------------------------------------------- #
def md4(data):
    """Implementacion de MD4 (RFC 1320) en Python puro. Devuelve bytes."""
    def _izq(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    largo = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += largo.to_bytes(8, "little")

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little")
             for i in range(16)]
        aa, bb, cc, dd = a, b, c, d

        def f(x, y, z):
            return (x & y) | (~x & z)

        def g(x, y, z):
            return (x & y) | (x & z) | (y & z)

        def h(x, y, z):
            return x ^ y ^ z

        for i in range(4):
            k = 4 * i
            a = _izq(a + f(b, c, d) + x[k], 3)
            d = _izq(d + f(a, b, c) + x[k + 1], 7)
            c = _izq(c + f(d, a, b) + x[k + 2], 11)
            b = _izq(b + f(c, d, a) + x[k + 3], 19)
        for i in range(4):
            a = _izq(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = _izq(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = _izq(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = _izq(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)
        orden = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(0, 16, 4):
            a = _izq(a + h(b, c, d) + x[orden[i]] + 0x6ED9EBA1, 3)
            d = _izq(d + h(a, b, c) + x[orden[i + 1]] + 0x6ED9EBA1, 9)
            c = _izq(c + h(d, a, b) + x[orden[i + 2]] + 0x6ED9EBA1, 11)
            b = _izq(b + h(c, d, a) + x[orden[i + 3]] + 0x6ED9EBA1, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


def ntlm(password):
    """Hash NTLM = MD4(UTF-16LE(password)), en hex minusculas."""
    return md4(password.encode("utf-16le")).hex()


# --------------------------------------------------------------------------- #
#  Tipos de hash y funciones
# --------------------------------------------------------------------------- #
_FUNCS = {
    "md5": lambda p: hashlib.md5(p.encode("utf-8", "ignore")).hexdigest(),
    "sha1": lambda p: hashlib.sha1(p.encode("utf-8", "ignore")).hexdigest(),
    "sha256": lambda p: hashlib.sha256(p.encode("utf-8", "ignore")).hexdigest(),
    "sha512": lambda p: hashlib.sha512(p.encode("utf-8", "ignore")).hexdigest(),
    "ntlm": ntlm,
}


def identificar(h):
    """Devuelve lista de tipos candidatos para el hash dado."""
    h = h.strip()
    if h.startswith("$2"):
        return ["bcrypt"]
    if h.startswith("$1$"):
        return ["md5crypt"]
    if h.startswith("$5$"):
        return ["sha256crypt"]
    if h.startswith("$6$"):
        return ["sha512crypt"]
    hl = h.lower()
    if hl and all(c in "0123456789abcdef" for c in hl):
        n = len(hl)
        if n == 32:
            return ["md5", "ntlm"]
        if n == 40:
            return ["sha1"]
        if n == 64:
            return ["sha256"]
        if n == 128:
            return ["sha512"]
    return ["desconocido"]


def _verificar_crypt(password, hash_objetivo):
    """Comprueba una contrasena contra un hash unix crypt ($1$/$5$/$6$)."""
    if not _crypt:
        return False
    try:
        return _crypt.crypt(password, hash_objetivo) == hash_objetivo
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Carga de hashes
# --------------------------------------------------------------------------- #
def cargar_hashes(texto):
    """Parsea hashes desde texto pegado o contenido de archivo.

    Acepta por linea: 'hash', 'usuario:hash' o shadow 'usuario:$6$...:...'.
    Devuelve lista de dicts: {usuario, hash, tipos}.
    """
    entradas = []
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        usuario, h = "", linea
        if ":" in linea:
            partes = linea.split(":")
            if len(partes) >= 2 and partes[1].startswith("$"):
                usuario, h = partes[0], partes[1]
            elif len(partes) == 2 and partes[1]:
                usuario, h = partes[0], partes[1]
            else:
                h = partes[-1] if partes[-1] else partes[0]
        h = h.strip()
        if not h:
            continue
        entradas.append({"usuario": usuario, "hash": h, "tipos": identificar(h)})
    return entradas


# --------------------------------------------------------------------------- #
#  Crackeo
# --------------------------------------------------------------------------- #
def _iter_wordlist(ruta):
    """Itera palabras de una wordlist; si no hay ruta usa la lista embebida."""
    if ruta:
        try:
            with open(ruta, "r", encoding="latin-1", errors="ignore") as f:
                for linea in f:
                    yield linea.rstrip("\r\n")
            return
        except OSError:
            pass
    for w in sorted(password_audit.COMUNES):
        yield w


def _probar(entrada, palabra):
    """True si `palabra` genera el hash de `entrada` (segun sus tipos)."""
    objetivo = entrada["hash"]
    for tipo in entrada["tipos"]:
        if tipo in _FUNCS:
            if _FUNCS[tipo](palabra) == objetivo.lower():
                return True
        elif tipo in ("md5crypt", "sha256crypt", "sha512crypt"):
            if _verificar_crypt(palabra, objetivo):
                return True
    return False


def crackear_diccionario(entradas, ruta_wordlist=None, callback=None):
    """Ataque por diccionario. Devuelve {hash: plaintext} de los encontrados."""
    pendientes = [e for e in entradas if e["tipos"][0] != "desconocido"]
    encontrados = {}
    intentos = 0
    for palabra in _iter_wordlist(ruta_wordlist):
        if not pendientes:
            break
        intentos += 1
        if callback and intentos % 2000 == 0:
            callback(intentos, len(encontrados))
        restantes = []
        for e in pendientes:
            if _probar(e, palabra):
                encontrados[e["hash"]] = palabra
            else:
                restantes.append(e)
        pendientes = restantes
    if callback:
        callback(intentos, len(encontrados))
    return encontrados


def crackear_fuerza_bruta(entradas, max_len=4, callback=None):
    """Fuerza bruta educativa (lento). charset: minusculas + digitos."""
    charset = string.ascii_lowercase + string.digits
    pendientes = [e for e in entradas if e["tipos"][0] in _FUNCS]
    encontrados = {}
    intentos = 0
    for largo in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=largo):
            if not pendientes:
                return encontrados
            palabra = "".join(combo)
            intentos += 1
            if callback and intentos % 20000 == 0:
                callback(intentos, len(encontrados))
            restantes = []
            for e in pendientes:
                if _probar(e, palabra):
                    encontrados[e["hash"]] = palabra
                else:
                    restantes.append(e)
            pendientes = restantes
    if callback:
        callback(intentos, len(encontrados))
    return encontrados


def nota_entorno():
    """Mensaje sobre soporte de crypt en el SO actual."""
    if _crypt:
        return "crypt disponible: $1$/$5$/$6$ soportados."
    return ("crypt no disponible en este SO (Windows): $1$/$5$/$6$ requieren "
            "Linux. MD5/SHA1/SHA256/SHA512/NTLM si funcionan.")
