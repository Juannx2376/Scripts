"""Escaner de puertos TCP/UDP nativo (reemplazo de Nmap).

Usa solo sockets de la biblioteca estandar, sin privilegios:
  - TCP: "connect scan" (socket.connect). Fiable y sin root.
  - UDP: envio de datagrama + espera de respuesta. Best-effort, porque UDP
    no confirma puertos abiertos salvo que el servicio responda.

Incluye banner grabbing basico para inferir el servicio real.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Mil puertos TCP mas comunes (subconjunto practico del top-ports de nmap).
TOP_PUERTOS = [
    7, 20, 21, 22, 23, 25, 37, 53, 67, 68, 69, 79, 80, 81, 88, 110, 111, 113,
    119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 199, 389, 427, 443, 445,
    465, 500, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990,
    993, 995, 1025, 1026, 1027, 1080, 1194, 1433, 1434, 1521, 1723, 1900, 2000,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000,
    3128, 3268, 3306, 3389, 3690, 4000, 4444, 4567, 4848, 5000, 5060, 5061,
    5432, 5555, 5601, 5672, 5900, 5984, 6000, 6379, 6443, 6660, 6667, 7001,
    7070, 7077, 8000, 8008, 8009, 8080, 8081, 8083, 8086, 8088, 8089, 8090,
    8161, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9600,
    9999, 10000, 11211, 15672, 16379, 27017, 27018, 28017, 50000, 50070, 61616,
]

SERVICIOS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1900: "upnp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    3000: "dev-http", 3128: "squid", 3306: "mysql", 3389: "rdp",
    5060: "sip", 5432: "postgres", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6443: "kubernetes", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}


def nombre_servicio(puerto):
    """Nombre probable del servicio segun el numero de puerto."""
    return SERVICIOS.get(puerto, "desconocido")


def _grab_banner(sock):
    """Intenta leer un banner corto del servicio ya conectado."""
    try:
        sock.settimeout(1.0)
        datos = sock.recv(128)
        return datos.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def escanear_puerto_tcp(ip, puerto, timeout=1.0):
    """Devuelve (puerto, abierto_bool, banner_o_None) para un puerto TCP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, puerto)) == 0:
                return puerto, True, _grab_banner(s)
        except OSError:
            pass
    return puerto, False, None


def escanear_puerto_udp(ip, puerto, timeout=1.5):
    """Sondea un puerto UDP. Devuelve (puerto, estado).

    Estados posibles:
      - "abierto"        -> el servicio respondio
      - "abierto|filtrado" -> sin respuesta (normal en UDP)
      - "cerrado"        -> se recibio ICMP port-unreachable (ConnectionReset)
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(b"\x00", (ip, puerto))
            s.recvfrom(1024)
            return puerto, "abierto"
        except socket.timeout:
            return puerto, "abierto|filtrado"
        except ConnectionResetError:
            return puerto, "cerrado"
        except OSError:
            return puerto, "cerrado"


def escanear_tcp(ip, puertos=None, hilos=200, timeout=1.0, callback=None):
    """Escaneo TCP concurrente. Devuelve lista de dicts de puertos abiertos."""
    if puertos is None:
        puertos = TOP_PUERTOS
    puertos = list(puertos)
    abiertos = []
    hilos = max(1, min(hilos, len(puertos))) if puertos else 1

    with ThreadPoolExecutor(max_workers=hilos) as pool:
        futuros = {
            pool.submit(escanear_puerto_tcp, ip, p, timeout): p for p in puertos
        }
        for futuro in as_completed(futuros):
            try:
                puerto, abierto, banner = futuro.result()
            except Exception:
                continue
            if callback:
                callback(puerto, abierto)
            if abierto:
                abiertos.append(
                    {
                        "puerto": puerto,
                        "servicio": nombre_servicio(puerto),
                        "banner": banner,
                    }
                )

    abiertos.sort(key=lambda d: d["puerto"])
    return abiertos


def escanear_udp(ip, puertos=None, hilos=100, timeout=1.5, callback=None):
    """Escaneo UDP concurrente. Devuelve lista de dicts (omite cerrados)."""
    if puertos is None:
        # Pocos puertos UDP por defecto: UDP es lento y ruidoso.
        puertos = [53, 67, 68, 69, 123, 137, 138, 161, 500, 1900, 5353]
    puertos = list(puertos)
    resultado = []
    hilos = max(1, min(hilos, len(puertos))) if puertos else 1

    with ThreadPoolExecutor(max_workers=hilos) as pool:
        futuros = {
            pool.submit(escanear_puerto_udp, ip, p, timeout): p for p in puertos
        }
        for futuro in as_completed(futuros):
            try:
                puerto, estado = futuro.result()
            except Exception:
                continue
            if callback:
                callback(puerto, estado != "cerrado")
            if estado != "cerrado":
                resultado.append(
                    {
                        "puerto": puerto,
                        "servicio": nombre_servicio(puerto),
                        "estado": estado,
                    }
                )

    resultado.sort(key=lambda d: d["puerto"])
    return resultado


def parsear_rango_puertos(texto):
    """Convierte '22,80,443' o '1-1024' o '1-100,443' en lista de enteros."""
    puertos = set()
    for parte in texto.replace(" ", "").split(","):
        if not parte:
            continue
        if "-" in parte:
            ini, fin = parte.split("-", 1)
            ini, fin = int(ini), int(fin)
            if ini > fin:
                ini, fin = fin, ini
            puertos.update(range(max(1, ini), min(65535, fin) + 1))
        else:
            p = int(parte)
            if 1 <= p <= 65535:
                puertos.add(p)
    return sorted(puertos)
