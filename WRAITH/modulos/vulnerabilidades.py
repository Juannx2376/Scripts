"""Analizador de vulnerabilidades (equivalente nativo a `nmap -sC --script vuln`).

Dos motores complementarios, ambos NO explotadores (solo identifican):

1) Motor CVE: cruza el producto/version detectado por servicios.py contra una
   base local y curada de vulnerabilidades conocidas. Cada hallazgo incluye
   CVE, severidad y remediacion.

2) Scripts seguros (estilo NSE default/-sC): comprobaciones de reconocimiento
   no intrusivas sobre servicios abiertos (cabeceras HTTP, metodos, robots,
   TLS debil, FTP anonimo, SMBv1, etc.). No prueban credenciales ni explotan.

Aviso: la base CVE es ilustrativa y ampliable. Un hallazgo "potencial" indica
coincidencia por version; confirma siempre manualmente antes de concluir.
"""

import platform
import re
import socket
import ssl
import struct

# --------------------------------------------------------------------------- #
#  Comparacion de versiones
# --------------------------------------------------------------------------- #
def _tupla_version(v):
    """'2.4.49' -> (2,4,49). Ignora sufijos como 'p1' tomando solo numeros."""
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums) if nums else ()


def _cmp(v1, v2):
    t1, t2 = _tupla_version(v1), _tupla_version(v2)
    # Igualar longitudes con ceros.
    n = max(len(t1), len(t2))
    t1 += (0,) * (n - len(t1))
    t2 += (0,) * (n - len(t2))
    return (t1 > t2) - (t1 < t2)


def _en_rango(version, menor_que=None, desde=None, hasta=None, igual=None):
    """Evalua una condicion de version contra los limites dados."""
    if not version:
        return False
    if igual is not None:
        return _tupla_version(version) == _tupla_version(igual)
    if menor_que is not None and _cmp(version, menor_que) >= 0:
        return False
    if desde is not None and _cmp(version, desde) < 0:
        return False
    if hasta is not None and _cmp(version, hasta) > 0:
        return False
    return True


# --------------------------------------------------------------------------- #
#  Base de datos CVE (curada, real y ampliable)
#  Cada entrada: clave=producto en minusculas -> lista de reglas.
#  Regla: {cond, cve, cvss, sev, titulo, remediacion}
#    cond: dict pasado a _en_rango (menor_que/desde/hasta/igual) o None (aplica
#          a cualquier version del producto).
# --------------------------------------------------------------------------- #
_CVE_DB_EMBED = {
    "openssh": [
        {"cond": {"menor_que": "7.7"}, "cve": "CVE-2018-15473", "cvss": 5.3,
         "sev": "Media", "titulo": "Enumeracion de usuarios por tiempos",
         "remediacion": "Actualizar OpenSSH a 7.7 o superior."},
        {"cond": {"menor_que": "9.3p2"}, "cve": "CVE-2023-38408", "cvss": 9.8,
         "sev": "Critica", "titulo": "RCE via ssh-agent (PKCS#11)",
         "remediacion": "Actualizar a OpenSSH 9.3p2+; no reenviar ssh-agent."},
    ],
    "vsftpd": [
        {"cond": {"igual": "2.3.4"}, "cve": "CVE-2011-2523", "cvss": 10.0,
         "sev": "Critica", "titulo": "Backdoor en vsftpd 2.3.4 (shell en :6200)",
         "remediacion": "Reemplazar por una version oficial no comprometida."},
    ],
    "proftpd": [
        {"cond": {"igual": "1.3.5"}, "cve": "CVE-2015-3306", "cvss": 10.0,
         "sev": "Critica", "titulo": "mod_copy permite lectura/escritura arbitraria",
         "remediacion": "Actualizar a 1.3.5a+ o deshabilitar mod_copy."},
    ],
    "apache httpd": [
        {"cond": {"igual": "2.4.49"}, "cve": "CVE-2021-41773", "cvss": 7.5,
         "sev": "Alta", "titulo": "Path traversal / RCE en Apache 2.4.49",
         "remediacion": "Actualizar a 2.4.51 o superior."},
        {"cond": {"igual": "2.4.50"}, "cve": "CVE-2021-42013", "cvss": 9.8,
         "sev": "Critica", "titulo": "Path traversal / RCE en Apache 2.4.50",
         "remediacion": "Actualizar a 2.4.51 o superior."},
    ],
    "nginx": [
        {"cond": {"desde": "0.5.6", "hasta": "1.13.2"}, "cve": "CVE-2017-7529",
         "cvss": 7.5, "sev": "Alta", "titulo": "Fuga de memoria por integer overflow en range",
         "remediacion": "Actualizar a nginx 1.13.3 / 1.12.1 o superior."},
    ],
    "iis": [
        {"cond": {"igual": "6.0"}, "cve": "CVE-2017-7269", "cvss": 9.8,
         "sev": "Critica", "titulo": "Buffer overflow en WebDAV (IIS 6.0)",
         "remediacion": "Migrar fuera de IIS 6.0 (sin soporte)."},
    ],
    "mariadb": [
        {"cond": None, "cve": "N/A", "cvss": 0.0, "sev": "Info",
         "titulo": "Servicio de base de datos expuesto a la red",
         "remediacion": "Restringir acceso por firewall; no exponer a Internet."},
    ],
    "mysql": [
        {"cond": None, "cve": "N/A", "cvss": 0.0, "sev": "Info",
         "titulo": "Servicio de base de datos expuesto a la red",
         "remediacion": "Restringir acceso por firewall; usuarios con contrasena fuerte."},
    ],
    "redis": [
        {"cond": None, "cve": "N/A", "cvss": 8.0, "sev": "Alta",
         "titulo": "Redis suele exponerse sin autenticacion (RCE via config)",
         "remediacion": "Activar 'requirepass', 'protected-mode yes' y bind local."},
    ],
    "apache tomcat": [
        {"cond": {"desde": "9.0.0", "hasta": "9.0.30"}, "cve": "CVE-2020-1938",
         "cvss": 9.8, "sev": "Critica",
         "titulo": "Ghostcat: lectura/inclusion de archivos via AJP",
         "remediacion": "Actualizar Tomcat y deshabilitar el conector AJP si no se usa."},
    ],
    "elasticsearch": [
        {"cond": None, "cve": "N/A", "cvss": 7.5, "sev": "Alta",
         "titulo": "Elasticsearch suele exponerse sin autenticacion",
         "remediacion": "Activar seguridad (xpack), autenticacion y bind local."},
    ],
    "mongodb": [
        {"cond": None, "cve": "N/A", "cvss": 7.5, "sev": "Alta",
         "titulo": "MongoDB puede exponerse sin autenticacion",
         "remediacion": "Activar autenticacion y bind local; no exponer a Internet."},
    ],
}

# Reglas basadas en el puerto (SMB/EternalBlue se evalua aparte, de forma activa).
_CVE_POR_PUERTO_EMBED = {
    3389: {"cve": "CVE-2019-0708 (BlueKeep)", "cvss": 9.8, "sev": "Critica",
           "titulo": "RDP potencialmente vulnerable a BlueKeep si no esta parcheado",
           "remediacion": "Aplicar parche; activar NLA; no exponer RDP a Internet."},
}


def _cargar_cve_db():
    """Carga cve_db.json si existe; si no, usa la base embebida (fallback).

    Permite ampliar la base sin tocar codigo (estilo feed de Nessus/OpenVAS) y
    mantiene funcional el archivo unificado wraith.py cuando el JSON no esta.
    """
    import json
    import os
    try:
        ruta = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "cve_db.json")
        with open(ruta, "r", encoding="utf-8") as f:
            data = json.load(f)
        productos = data.get("productos", {})
        por_puerto = {int(k): v for k, v in data.get("por_puerto", {}).items()}
        if productos:
            return productos, (por_puerto or _CVE_POR_PUERTO_EMBED)
    except Exception:
        # Incluye el caso del archivo unificado (sin __file__ ni cve_db.json):
        # se usa la base embebida completa de abajo.
        pass
    return _CVE_DB_EMBED, _CVE_POR_PUERTO_EMBED


CVE_DB, CVE_POR_PUERTO = _cargar_cve_db()


# --------------------------------------------------------------------------- #
#  EternalBlue (MS17-010): auto-deteccion por negociacion SMBv1
#
#  EternalBlue SOLO afecta a objetivos con SMBv1 habilitado. En vez de alertar
#  siempre que el puerto 445 este abierto, se negocia SMBv1 realmente:
#    - Si el objetivo acepta SMBv1  -> potencialmente vulnerable.
#    - Si solo habla SMB2/SMB3      -> EternalBlue se descarta automaticamente.
#  Windows 10/11 modernos traen SMBv1 desactivado por defecto, por lo que el
#  hallazgo se descarta solo sin necesidad de conocer la version exacta.
# --------------------------------------------------------------------------- #
def _paquete_negociacion_smbv1():
    """'SMB1 Negotiate Protocol Request' sobre TCP directo (445)."""
    dialectos = [
        b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0",
        b"Windows for Workgroups 3.1a", b"LM1.2X002",
        b"LANMAN2.1", b"NT LM 0.12",
        # Dialectos SMB2 para que un host con SMBv1 apagado responda con SMB2
        # (\xfeSMB) en vez de ignorar la negociacion -> descarte fiable.
        b"SMB 2.002", b"SMB 2.???",
    ]
    datos = b"".join(b"\x02" + d + b"\x00" for d in dialectos)
    cabecera = (
        b"\xffSMB"
        b"\x72"
        b"\x00\x00\x00\x00"
        b"\x18"
        b"\x53\xc8"
        b"\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x2f\x4b"
        b"\x00\x00"
        b"\xc5\x5e"
    )
    smb = cabecera + b"\x00" + struct.pack("<H", len(datos)) + datos
    netbios = b"\x00" + struct.pack(">I", len(smb))[1:]
    return netbios + smb


def comprobar_smbv1(ip, timeout=4.0):
    """Devuelve True (SMBv1 on), False (solo SMB2/3) o None (indeterminado)."""
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as s:
            s.sendall(_paquete_negociacion_smbv1())
            s.settimeout(timeout)
            resp = s.recv(1024)
    except OSError:
        return None
    if not resp:
        return None
    if b"\xffSMB" in resp:
        return True
    if b"\xfeSMB" in resp or b"\xfdSMB" in resp:
        return False
    return None


def _objetivo_es_local(ip):
    """True si el objetivo es esta misma maquina (para poder leer su SO)."""
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    try:
        from modulos import red
        return ip == red.ip_local_salida()
    except Exception:
        return False


def evaluar_eternalblue(ip):
    """Evalua MS17-010 de forma activa; se auto-descarta cuando no aplica."""
    if _objetivo_es_local(ip) and platform.system().lower().startswith("win") \
            and platform.release() == "11":
        return {
            "tipo": "CVE", "cve": "MS17-010", "cvss": 0.0, "sev": "Info",
            "titulo": "EternalBlue descartado: Windows 11 (SMBv1 off por defecto)",
            "remediacion": "Mantener SMBv1 deshabilitado.",
            "evidencia": "SO local = Windows 11"}

    estado = comprobar_smbv1(ip)
    if estado is True:
        return {
            "tipo": "CVE", "cve": "MS17-010 / CVE-2017-0144", "cvss": 8.1,
            "sev": "Critica", "titulo": "SMBv1 HABILITADO: expuesto a EternalBlue",
            "remediacion": "Deshabilitar SMBv1 y aplicar el parche MS17-010.",
            "evidencia": "El objetivo acepto la negociacion SMBv1"}
    if estado is False:
        return {
            "tipo": "CVE", "cve": "MS17-010", "cvss": 0.0, "sev": "Info",
            "titulo": "EternalBlue descartado: SMBv1 deshabilitado en el objetivo",
            "remediacion": "Mantener SMBv1 deshabilitado.",
            "evidencia": "El objetivo solo negocia SMB2/3"}
    return {
        "tipo": "CVE", "cve": "MS17-010 / CVE-2017-0144", "cvss": 5.0,
        "sev": "Media", "titulo": "Posible EternalBlue (no se confirmo SMBv1)",
        "remediacion": "Verificar manualmente si SMBv1 esta habilitado.",
        "evidencia": "Sin respuesta concluyente a la negociacion SMBv1"}


def _buscar_cve(producto, version):
    """Devuelve lista de hallazgos CVE para producto/version dados."""
    hallazgos = []
    clave = (producto or "").strip().lower()
    reglas = CVE_DB.get(clave)
    # Coincidencia parcial (p.ej. "apache httpd (ubuntu)").
    if not reglas:
        for k, v in CVE_DB.items():
            if k in clave:
                reglas = v
                break
    if not reglas:
        return hallazgos

    for regla in reglas:
        cond = regla["cond"]
        aplica = True if cond is None else _en_rango(version, **cond)
        if aplica:
            hallazgos.append({
                "tipo": "CVE",
                "cve": regla["cve"], "cvss": regla["cvss"], "sev": regla["sev"],
                "titulo": regla["titulo"], "remediacion": regla["remediacion"],
                "evidencia": f"{producto} {version}".strip(),
            })
    return hallazgos


# --------------------------------------------------------------------------- #
#  Scripts seguros (estilo -sC)
# --------------------------------------------------------------------------- #
def _hallazgo(sev, titulo, detalle="", remediacion="", cve="-", cvss=0.0):
    return {"tipo": "script", "sev": sev, "titulo": titulo, "evidencia": detalle,
            "remediacion": remediacion, "cve": cve, "cvss": cvss}


def script_http(ip, puerto, usar_tls, timeout=3.0):
    """Cabeceras de seguridad, metodos permitidos y robots.txt."""
    hallazgos = []
    try:
        raw = socket.create_connection((ip, puerto), timeout=timeout)
    except OSError:
        return hallazgos
    sock = raw
    try:
        if usar_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        sock.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
        )
        sock.settimeout(timeout)
        resp = b""
        while len(resp) < 4096:
            try:
                t = sock.recv(2048)
            except OSError:
                break
            if not t:
                break
            resp += t
        texto = resp.decode("latin-1", errors="replace").lower()
    finally:
        try:
            sock.close()
        except OSError:
            pass

    faltan = []
    for cab, nombre in [
        ("strict-transport-security", "HSTS"),
        ("content-security-policy", "CSP"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
    ]:
        if cab not in texto:
            faltan.append(nombre)
    if faltan:
        hallazgos.append(_hallazgo(
            "Baja", "Cabeceras de seguridad HTTP ausentes",
            "Faltan: " + ", ".join(faltan),
            "Agregar las cabeceras de seguridad faltantes en el servidor web."))
    if "server:" in texto:
        srv = re.search(r"server:\s*(.+)", texto)
        if srv:
            hallazgos.append(_hallazgo(
                "Info", "Banner de servidor divulgado", srv.group(1).strip(),
                "Ocultar/minimizar la cabecera Server (ServerTokens Prod)."))
    return hallazgos


def script_ftp_anon(ip, puerto, timeout=4.0):
    """Comprueba si el FTP permite login anonimo (comprobacion estandar y segura)."""
    hallazgos = []
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            s.settimeout(timeout)
            s.recv(256)
            s.sendall(b"USER anonymous\r\n")
            s.recv(256)
            s.sendall(b"PASS anonymous@test.com\r\n")
            resp = s.recv(256).decode("latin-1", errors="replace")
            if resp.startswith("230"):
                hallazgos.append(_hallazgo(
                    "Media", "FTP permite acceso anonimo", resp.strip(),
                    "Deshabilitar el acceso anonimo salvo que sea necesario."))
    except OSError:
        pass
    return hallazgos


def script_tls_debil(ip, puerto, timeout=4.0):
    """Detecta protocolos TLS obsoletos y certificado autofirmado/expirado."""
    hallazgos = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, puerto), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                proto = s.version() or ""
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    hallazgos.append(_hallazgo(
                        "Media", "Protocolo TLS/SSL obsoleto negociado", proto,
                        "Deshabilitar SSLv3/TLS1.0/1.1; usar TLS 1.2+."))
    except (OSError, ssl.SSLError):
        pass
    return hallazgos


def _puerto_abierto(ip, puerto, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, puerto)) == 0


# --------------------------------------------------------------------------- #
#  Orquestador
# --------------------------------------------------------------------------- #
def analizar(ip, servicios_detectados, correr_scripts=True):
    """Analiza una lista de servicios (de servicios.detectar_varios).

    Devuelve lista de hallazgos, cada uno con puerto asociado.
    """
    todos = []
    puertos_abiertos = {svc["puerto"] for svc in servicios_detectados}

    # EternalBlue: se evalua UNA sola vez y solo si hay SMB expuesto (139/445).
    if puertos_abiertos & {139, 445}:
        eb = evaluar_eternalblue(ip)
        eb["puerto"] = 445 if 445 in puertos_abiertos else 139
        eb["servicio"] = "smb"
        todos.append(eb)

    for svc in servicios_detectados:
        puerto = svc["puerto"]
        hallazgos_puerto = []

        # 1) Motor CVE por producto/version.
        hallazgos_puerto += _buscar_cve(svc.get("producto", ""), svc.get("version", ""))

        # 2) Reglas por puerto (RDP, ...; SMB se maneja arriba).
        if puerto in CVE_POR_PUERTO:
            r = CVE_POR_PUERTO[puerto]
            hallazgos_puerto.append({
                "tipo": "CVE", "cve": r["cve"], "cvss": r["cvss"], "sev": r["sev"],
                "titulo": r["titulo"], "remediacion": r["remediacion"],
                "evidencia": f"puerto {puerto} abierto"})

        # 3) Scripts seguros segun el servicio.
        if correr_scripts:
            serv = svc.get("servicio", "")
            try:
                if serv in ("http", "https"):
                    hallazgos_puerto += script_http(ip, puerto, serv == "https")
                    if serv == "https":
                        hallazgos_puerto += script_tls_debil(ip, puerto)
                elif serv == "ftp" or puerto == 21:
                    hallazgos_puerto += script_ftp_anon(ip, puerto)
                elif puerto in PUERTOS_TLS_GENERICO:
                    hallazgos_puerto += script_tls_debil(ip, puerto)
            except Exception:
                pass

        for h in hallazgos_puerto:
            h["puerto"] = puerto
            h["servicio"] = svc.get("servicio", "")
            todos.append(h)

    # Orden por severidad (Critica primero).
    todos.sort(key=lambda h: _ORDEN_SEV.get(h["sev"], 99))
    return todos


PUERTOS_TLS_GENERICO = {443, 993, 995, 465, 8443, 636}
_ORDEN_SEV = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Info": 4}
