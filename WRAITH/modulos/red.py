"""Obtencion de interfaces, IPs y calculo de subredes.

Reemplazo nativo de la logica de rutas de scapy (conf.route).
Funciona en Windows y Linux usando solo la biblioteca estandar:
  - socket  -> para averiguar la IP local de salida
  - subprocess (ipconfig / ip / ifconfig) -> para la mascara de red
  - ipaddress -> para calcular la subred
"""

import ipaddress
import platform
import re
import socket
import subprocess

ES_WINDOWS = platform.system().lower().startswith("win")


def ip_local_salida(destino="8.8.8.8"):
    """Devuelve la IP local que el SO usaria para salir hacia `destino`.

    Truco clasico: abrir un socket UDP (no envia nada) y preguntar que
    direccion local le asigna el kernel. No requiere permisos.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((destino, 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _ejecutar(comando):
    """Ejecuta un comando del sistema y devuelve su salida como texto."""
    try:
        salida = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return salida.stdout + salida.stderr
    except (subprocess.SubprocessError, OSError):
        return ""


def _mascara_windows(ip):
    """Extrae la mascara de red asociada a `ip` parseando `ipconfig`."""
    texto = _ejecutar(["ipconfig"])
    # Agrupamos por bloques de adaptador; buscamos el que contiene nuestra IP.
    ip_re = re.escape(ip)
    patron = re.compile(
        r"IPv4.*?:\s*" + ip_re + r".*?(?:M[aá]scara|Subnet Mask).*?:\s*"
        r"(\d+\.\d+\.\d+\.\d+)",
        re.IGNORECASE | re.DOTALL,
    )
    m = patron.search(texto)
    if m:
        return m.group(1)
    return None


def _mascara_linux(ip):
    """Extrae la mascara (prefijo CIDR) asociada a `ip` usando `ip addr`.

    Primero intenta `ip -o addr` (iproute2), luego `ifconfig` como respaldo.
    """
    texto = _ejecutar(["ip", "-o", "-f", "inet", "addr", "show"])
    if texto:
        # Lineas del tipo: "2: eth0    inet 192.168.1.10/24 brd ..."
        for linea in texto.splitlines():
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", linea)
            if m and m.group(1) == ip:
                prefijo = int(m.group(2))
                return str(ipaddress.IPv4Network(f"0.0.0.0/{prefijo}").netmask)

    # Respaldo: ifconfig (sistemas antiguos / BSD)
    texto = _ejecutar(["ifconfig"])
    if texto:
        ip_re = re.escape(ip)
        m = re.search(
            ip_re + r".*?(?:netmask|Mask)[:\s]+(\S+)",
            texto,
            re.IGNORECASE | re.DOTALL,
        )
        if m:
            mascara = m.group(1)
            # ifconfig de Linux a veces da la mascara en hex: 0xffffff00
            if mascara.lower().startswith("0x"):
                entero = int(mascara, 16)
                return socket.inet_ntoa(entero.to_bytes(4, "big"))
            return mascara
    return None


def obtener_interfaz(destino="8.8.8.8"):
    """Devuelve dict con la interfaz de salida: name (si se puede), ip, netmask.

    Si no se logra deducir la mascara, asume /24 (255.255.255.0), que es la
    configuracion domestica mas habitual.
    """
    ip = ip_local_salida(destino)
    if ip == "127.0.0.1":
        raise RuntimeError("No se encontro una interfaz con salida a la red.")

    if ES_WINDOWS:
        mascara = _mascara_windows(ip)
    else:
        mascara = _mascara_linux(ip)

    if not mascara:
        mascara = "255.255.255.0"

    return {"name": _nombre_interfaz(ip), "ip": ip, "netmask": mascara}


def _nombre_interfaz(ip):
    """Mejor esfuerzo para nombrar la interfaz; no es critico si falla."""
    try:
        return socket.gethostname()
    except OSError:
        return "desconocida"


def calcular_red(ip, netmask):
    """Devuelve el objeto IPv4Network de la subred (host bits a 0)."""
    return ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)


def hosts_de_red(red, max_hosts=1024):
    """Lista de IPs utilizables de la subred, con tope de seguridad.

    Evita generar millones de direcciones si alguien pasa una /8 por error.
    """
    hosts = []
    for i, host in enumerate(red.hosts()):
        if i >= max_hosts:
            break
        hosts.append(str(host))
    return hosts
