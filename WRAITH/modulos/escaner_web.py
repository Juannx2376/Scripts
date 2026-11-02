"""Auditor web nativo (estilo Nikto, no Burp/Repeater).

Reconocimiento automatico y NO intrusivo de un servicio web:
  - Enumeracion de rutas/archivos sensibles comunes (wordlist embebida).
  - Cabeceras de seguridad ausentes y banner del servidor.
  - Flags de cookies (HttpOnly / Secure).
  - CORS permisivo (Access-Control-Allow-Origin: *).
  - Metodos HTTP peligrosos habilitados (PUT/DELETE/TRACE) via OPTIONS.
  - robots.txt (rutas que el administrador intenta ocultar).

No hace fuzzing agresivo, no prueba credenciales y no modifica nada: solo
peticiones GET/HEAD/OPTIONS de lectura. Pensado para aprender que expone un web.
"""

import socket
import ssl

# Rutas sensibles habituales (archivos de configuracion, backups, paneles...).
RUTAS_SENSIBLES = [
    "/.git/HEAD", "/.env", "/.htaccess", "/config.php", "/wp-config.php",
    "/wp-config.php.bak", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/admin", "/admin/login", "/administrator", "/manager/html", "/.svn/entries",
    "/.DS_Store", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/api", "/api/v1", "/swagger.json", "/actuator", "/actuator/env",
    "/console", "/debug", "/test.php", "/login", "/.idea/workspace.xml",
]


def _conectar(ip, puerto, usar_tls, timeout):
    raw = socket.create_connection((ip, puerto), timeout=timeout)
    if usar_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=ip)
    return raw


def _peticion(ip, puerto, usar_tls, metodo, ruta, host=None, timeout=4.0,
              extra_cabeceras=""):
    """Envia una peticion HTTP simple y devuelve (status, cabeceras, cuerpo)."""
    host = host or ip
    try:
        s = _conectar(ip, puerto, usar_tls, timeout)
    except (OSError, ssl.SSLError):
        return None, "", ""
    try:
        pet = (f"{metodo} {ruta} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: wraith/1.0\r\nConnection: close\r\n"
               f"{extra_cabeceras}\r\n")
        s.sendall(pet.encode())
        s.settimeout(timeout)
        datos = b""
        while len(datos) < 16384:
            try:
                trozo = s.recv(4096)
            except OSError:
                break
            if not trozo:
                break
            datos += trozo
    finally:
        try:
            s.close()
        except OSError:
            pass

    texto = datos.decode("latin-1", errors="replace")
    partes = texto.split("\r\n\r\n", 1)
    cabeceras = partes[0]
    cuerpo = partes[1] if len(partes) > 1 else ""
    status = None
    primera = cabeceras.splitlines()[0] if cabeceras else ""
    m = primera.split(" ")
    if len(m) >= 2 and m[1].isdigit():
        status = int(m[1])
    return status, cabeceras, cuerpo


def _h(sev, titulo, detalle="", remediacion=""):
    return {"tipo": "web", "sev": sev, "titulo": titulo, "evidencia": detalle,
            "remediacion": remediacion, "cve": "-", "cvss": 0.0}


def _check_rutas(ip, puerto, usar_tls, host):
    hallazgos = []
    for ruta in RUTAS_SENSIBLES:
        status, _, _ = _peticion(ip, puerto, usar_tls, "GET", ruta, host)
        if status in (200, 401, 403):
            etiqueta = "accesible" if status == 200 else f"presente (HTTP {status})"
            sev = "Media" if status == 200 else "Baja"
            hallazgos.append(_h(
                sev, f"Ruta sensible {etiqueta}", f"{ruta} -> HTTP {status}",
                "Eliminar/restringir el recurso si no debe ser publico."))
    return hallazgos


def _check_cabeceras(cabeceras):
    hallazgos = []
    low = cabeceras.lower()
    faltan = []
    for cab, nombre in [
        ("strict-transport-security", "HSTS"),
        ("content-security-policy", "CSP"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
    ]:
        if cab not in low:
            faltan.append(nombre)
    if faltan:
        hallazgos.append(_h(
            "Baja", "Cabeceras de seguridad HTTP ausentes", ", ".join(faltan),
            "Agregar las cabeceras de seguridad faltantes en el servidor."))

    for linea in cabeceras.splitlines():
        ll = linea.lower()
        if ll.startswith("server:"):
            hallazgos.append(_h(
                "Info", "Banner de servidor divulgado", linea.split(":", 1)[1].strip(),
                "Minimizar la cabecera Server (p.ej. ServerTokens Prod)."))
        if ll.startswith("set-cookie:"):
            faltan_flags = []
            if "httponly" not in ll:
                faltan_flags.append("HttpOnly")
            if "secure" not in ll:
                faltan_flags.append("Secure")
            if faltan_flags:
                hallazgos.append(_h(
                    "Baja", "Cookie sin flags de seguridad",
                    "Falta: " + ", ".join(faltan_flags),
                    "Marcar las cookies con HttpOnly y Secure."))
        if ll.startswith("access-control-allow-origin:") and "*" in ll:
            hallazgos.append(_h(
                "Media", "CORS permisivo (Allow-Origin: *)", linea.strip(),
                "Restringir CORS a origenes de confianza."))
    return hallazgos


def _check_metodos(ip, puerto, usar_tls, host):
    hallazgos = []
    status, cabeceras, _ = _peticion(ip, puerto, usar_tls, "OPTIONS", "/", host)
    for linea in cabeceras.splitlines():
        if linea.lower().startswith("allow:"):
            metodos = linea.split(":", 1)[1].upper()
            peligrosos = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT")
                          if m in metodos]
            if peligrosos:
                hallazgos.append(_h(
                    "Media", "Metodos HTTP peligrosos habilitados",
                    ", ".join(peligrosos),
                    "Deshabilitar metodos no necesarios (PUT/DELETE/TRACE)."))
    return hallazgos


def _check_robots(ip, puerto, usar_tls, host):
    hallazgos = []
    status, _, cuerpo = _peticion(ip, puerto, usar_tls, "GET", "/robots.txt", host)
    if status == 200 and "disallow" in cuerpo.lower():
        rutas = [l.split(":", 1)[1].strip() for l in cuerpo.splitlines()
                 if l.lower().startswith("disallow") and ":" in l]
        rutas = [r for r in rutas if r][:10]
        if rutas:
            hallazgos.append(_h(
                "Info", "robots.txt revela rutas", ", ".join(rutas),
                "robots.txt no es un control de seguridad; no ocultar secretos ahi."))
    return hallazgos


def auditar_web(ip, puerto, usar_tls=False, host=None, timeout=4.0):
    """Ejecuta todas las comprobaciones web y devuelve lista de hallazgos."""
    host = host or ip
    hallazgos = []
    # Una peticion base para analizar cabeceras generales.
    _, cabeceras, _ = _peticion(ip, puerto, usar_tls, "GET", "/", host, timeout)
    if cabeceras:
        hallazgos += _check_cabeceras(cabeceras)
    hallazgos += _check_metodos(ip, puerto, usar_tls, host)
    hallazgos += _check_robots(ip, puerto, usar_tls, host)
    hallazgos += _check_rutas(ip, puerto, usar_tls, host)

    orden = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Info": 4}
    hallazgos.sort(key=lambda h: orden.get(h["sev"], 9))
    for h in hallazgos:
        h["puerto"] = puerto
        h["servicio"] = "https" if usar_tls else "http"
    return hallazgos
