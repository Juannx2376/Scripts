"""Descubrimiento de hosts en la red local (Ping Sweep multiplataforma).

Reemplazo nativo del ARP scan de scapy. En lugar de forjar paquetes ARP
(que requiere root/admin), se usa el binario `ping` del sistema operativo,
que cualquier usuario puede ejecutar.

Flujo:
  1. Ping sweep concurrente a toda la subred (ThreadPoolExecutor).
  2. Para los hosts que respondieron, se lee la tabla ARP del SO (`arp -a`)
     para obtener la MAC, igual que haria scapy pero sin privilegios.
"""

import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

ES_WINDOWS = platform.system().lower().startswith("win")


def _comando_ping(ip, timeout_ms=800):
    """Construye el comando ping con 1 solo paquete, segun el SO."""
    if ES_WINDOWS:
        # -n 1 (un eco), -w timeout en milisegundos
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    # Linux/macOS: -c 1 (un eco), -W timeout en segundos (minimo 1)
    timeout_s = max(1, round(timeout_ms / 1000))
    return ["ping", "-c", "1", "-W", str(timeout_s), ip]


def _host_responde(ip, timeout_ms=800):
    """True si el host responde al ping. Devuelve tambien el TTL si aparece."""
    try:
        res = subprocess.run(
            _comando_ping(ip, timeout_ms),
            capture_output=True,
            text=True,
            timeout=(timeout_ms / 1000) + 2,
        )
    except (subprocess.SubprocessError, OSError):
        return False, None

    salida = res.stdout + res.stderr

    # En Windows, "Host de destino inaccesible" sale con returncode 0 pero
    # NO es una respuesta real del host; hay que filtrarla.
    if ES_WINDOWS and re.search(r"inaccesible|unreachable", salida, re.IGNORECASE):
        return False, None

    vivo = res.returncode == 0 and bool(
        re.search(r"TTL[=:]", salida, re.IGNORECASE)
    )
    ttl = _extraer_ttl(salida) if vivo else None
    return vivo, ttl


def _extraer_ttl(salida):
    """Extrae el valor de TTL de la salida de ping (Windows y Linux)."""
    m = re.search(r"TTL[=:]\s*(\d+)", salida, re.IGNORECASE)
    return int(m.group(1)) if m else None


def ping_sweep(ips, hilos=100, timeout_ms=800, callback=None):
    """Hace ping concurrente a una lista de IPs.

    Devuelve dict {ip: ttl_o_None} solo con los hosts que respondieron.
    `callback(ip, vivo)` se invoca por cada host probado (para barra de progreso).
    """
    vivos = {}
    hilos = max(1, min(hilos, len(ips))) if ips else 1

    with ThreadPoolExecutor(max_workers=hilos) as pool:
        futuros = {pool.submit(_host_responde, ip, timeout_ms): ip for ip in ips}
        for futuro in as_completed(futuros):
            ip = futuros[futuro]
            try:
                vivo, ttl = futuro.result()
            except Exception:
                vivo, ttl = False, None
            if callback:
                callback(ip, vivo)
            if vivo:
                vivos[ip] = ttl

    return vivos


def leer_tabla_arp():
    """Lee la tabla ARP del SO y devuelve dict {ip: mac}.

    No requiere privilegios. Las MAC provienen de la cache ARP que el kernel
    rellena tras el ping sweep previo.
    """
    try:
        res = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return {}

    tabla = {}
    # MAC en formato Windows (aa-bb-cc-dd-ee-ff) o Unix (aa:bb:cc:dd:ee:ff)
    patron = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\D+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
    )
    for linea in (res.stdout + res.stderr).splitlines():
        m = patron.search(linea)
        if m:
            ip = m.group(1)
            mac = m.group(2).lower().replace("-", ":")
            tabla[ip] = mac
    return tabla
