#!/usr/bin/env python3
"""WRAITH - version unificada autocontenida.

Generado automaticamente por exportador.py a partir de los modulos del
proyecto. No requiere la carpeta modulos/. Multiplataforma (Windows/Linux).
"""

import sys
import types


def _registrar_modulo(nombre, codigo):
    """Crea un modulo en memoria desde codigo fuente y lo registra."""
    mod = types.ModuleType(nombre)
    mod.__dict__["__name__"] = nombre
    exec(compile(codigo, f"<{nombre}>", "exec"), mod.__dict__)
    sys.modules[nombre] = mod
    # Alias con prefijo de paquete para que "from modulos import X" funcione.
    sys.modules["modulos." + nombre] = mod
    return mod


# Paquete virtual "modulos" para que los imports del main resuelvan.
_paquete = types.ModuleType("modulos")
_paquete.__path__ = []  # marca como paquete
sys.modules["modulos"] = _paquete

# --- modulo: sistema ---
_CODIGO_SISTEMA = r'''"""Deteccion de SO y ejecucion de comandos, centralizada.

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
'''
_registrar_modulo("sistema", _CODIGO_SISTEMA)
setattr(_paquete, "sistema", sys.modules["sistema"])

# --- modulo: red ---
_CODIGO_RED = r'''"""Obtencion de interfaces, IPs y calculo de subredes.

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
'''
_registrar_modulo("red", _CODIGO_RED)
setattr(_paquete, "red", sys.modules["red"])

# --- modulo: escaner_local ---
_CODIGO_ESCANER_LOCAL = r'''"""Descubrimiento de hosts en la red local (Ping Sweep multiplataforma).

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
'''
_registrar_modulo("escaner_local", _CODIGO_ESCANER_LOCAL)
setattr(_paquete, "escaner_local", sys.modules["escaner_local"])

# --- modulo: escaner_externo ---
_CODIGO_ESCANER_EXTERNO = r'''"""Escaner de puertos TCP/UDP nativo (reemplazo de Nmap).

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
'''
_registrar_modulo("escaner_externo", _CODIGO_ESCANER_EXTERNO)
setattr(_paquete, "escaner_externo", sys.modules["escaner_externo"])

# --- modulo: identificador ---
_CODIGO_IDENTIFICADOR = r'''"""Logica de TTL, Hostname y Huella (Fingerprinting).

Reemplazo nativo de la base de fabricantes de scapy (conf.manufdb):
  - Hostname via DNS inverso (socket.gethostbyaddr).
  - SO probable segun el TTL observado en el ping.
  - Fabricante via tabla OUI embebida (prefijo de la MAC).
  - Tipo de dispositivo por reglas sobre el fabricante y, si falta, por
    los puertos abiertos detectados.
"""

import socket

# Prefijos OUI (primeros 3 bytes de la MAC) -> fabricante.
# Subconjunto representativo; ampliable sin dependencias externas.
OUI = {
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "00:1c:b3": "Apple",
    "ac:bc:32": "Apple",
    "f0:18:98": "Apple",
    "a4:83:e7": "Apple",
    "3c:5a:b4": "Google",
    "f4:f5:e8": "Google",
    "00:17:88": "Philips (Hue/IoT)",
    "18:b4:30": "Nest/Google",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox (innotek)",
    "00:15:5d": "Microsoft Hyper-V",
    "00:1c:42": "Parallels",
    "52:54:00": "QEMU/KVM",
    "00:1a:11": "Google",
    "fc:fb:fb": "Cisco",
    "00:1b:63": "Apple",
    "d8:3a:dd": "Raspberry Pi Trading",
    "e8:de:27": "TP-Link",
    "50:c7:bf": "TP-Link",
    "a4:2b:b0": "TP-Link",
    "c4:e9:84": "TP-Link",
    "14:cc:20": "TP-Link",
    "00:1d:0f": "TP-Link",
    "90:f6:52": "TP-Link",
    "00:26:5a": "D-Link",
    "1c:bd:b9": "D-Link",
    "c0:a0:bb": "D-Link",
    "20:4e:7f": "Netgear",
    "a0:40:a0": "Netgear",
    "48:f8:b3": "Cisco-Linksys",
    "00:25:9c": "Cisco-Linksys",
    "dc:9f:db": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    "74:83:c2": "Ubiquiti",
    "e0:63:da": "Ubiquiti",
    "4c:5e:0c": "MikroTik (Routerboard)",
    "64:d1:54": "MikroTik (Routerboard)",
    "cc:2d:e0": "MikroTik (Routerboard)",
    "00:1e:42": "MikroTik (Routerboard)",
    "ac:9e:17": "Asustek",
    "2c:56:dc": "Asustek",
    "04:92:26": "Asustek",
    "5c:cf:7f": "Espressif (ESP8266)",
    "24:0a:c4": "Espressif (ESP32)",
    "a4:cf:12": "Espressif (ESP32)",
    "cc:50:e3": "Espressif (ESP32)",
    "ec:fa:bc": "Espressif (ESP32)",
    "fc:f5:c4": "Espressif (ESP32)",
    "00:1a:22": "eQ-3/HomeMatic (IoT)",
    "d0:73:d5": "LIFX (IoT)",
    "b0:4e:26": "TP-Link (Kasa/IoT)",
    "50:02:91": "Espressif (IoT)",
    "f8:1a:67": "TP-Link",
    "00:12:fb": "Samsung",
    "5c:49:7d": "Samsung",
    "e8:50:8b": "Samsung",
    "bc:14:85": "Samsung",
    "28:6c:07": "Xiaomi",
    "64:09:80": "Xiaomi",
    "f8:a4:5f": "Xiaomi",
    "50:ec:50": "Xiaomi",
    "04:cf:8c": "Xiaomi",
    "00:9a:cd": "Huawei",
    "48:7b:6b": "Huawei",
    "e0:19:1d": "Huawei",
    "04:bd:88": "Aruba (HPE)",
    "6c:f3:7f": "Aruba (HPE)",
    "3c:07:54": "Apple",
    "68:54:5a": "Amazon (Echo/Fire)",
    "fc:65:de": "Amazon (Echo/Fire)",
    "44:65:0d": "Amazon (Echo/Fire)",
    "cc:f7:35": "Amazon (Echo/Fire)",
    "b0:a7:37": "Roku",
    "dc:3a:5e": "Roku",
    "00:0e:58": "Sonos",
    "5c:aa:fd": "Sonos",
    "94:9f:3e": "Sonos",
    "00:24:e4": "Withings (IoT)",
    "10:2c:6b": "Amazon (Echo/Fire)",
    "00:1d:d8": "Microsoft",
    "7c:1e:52": "Microsoft (Xbox/Surface)",
    "00:17:fa": "Microsoft",
    "00:21:5d": "IBM",
    "00:21:9b": "Dell",
    "18:03:73": "Dell",
    "d4:be:d9": "Dell",
    "f8:b1:56": "Dell",
    "00:21:70": "Dell",
    "3c:97:0e": "Wistron (laptops)",
    "00:1b:77": "Intel",
    "00:1e:64": "Intel",
    "a0:88:b4": "Intel",
    "34:13:e8": "Intel",
    "00:24:d7": "Intel",
    "88:53:2e": "Intel",
    "00:1f:16": "Wistron",
    "e4:b3:18": "Intel",
    "00:26:b9": "Dell",
    "00:1a:a0": "Dell",
    "00:1e:c9": "Dell",
    "ec:b1:d7": "Hewlett Packard",
    "70:5a:0f": "Hewlett Packard",
    "3c:d9:2b": "Hewlett Packard",
    "98:4b:e1": "Hewlett Packard",
    "00:1b:78": "Hewlett Packard",
    "a0:d3:c1": "Hewlett Packard",
    "00:23:ae": "Dell",
    "e8:9c:25": "Liteon (laptops)",
    "60:45:cb": "Asustek",
    "1c:1b:0d": "Gigabyte",
    "50:e5:49": "Gigabyte",
    "40:8d:5c": "Gigabyte",
    "d8:5e:d3": "Gigabyte",
    "70:85:c2": "ASRock",
    "00:d8:61": "MSI (Micro-Star)",
    "e0:d5:5e": "Giga-Byte",
    "4c:cc:6a": "Murata (modulos WiFi/IoT)",
    "40:f5:20": "Lenovo",
    "54:ee:75": "Wistron (Lenovo)",
    "50:7b:9d": "Lenovo",
    "a4:4c:c8": "Lenovo",
}

_REGLAS_TIPO = [
    (("raspberry",), "Raspberry Pi"),
    (("apple",), "Apple (iPhone/iPad/Mac)"),
    (("samsung",), "Samsung (movil/TV)"),
    (("xiaomi",), "Xiaomi (movil/IoT)"),
    (("huawei",), "Huawei (movil/router)"),
    (("espressif", "eq-3", "lifx", "withings", "murata"), "IoT (ESP/sensor)"),
    (
        ("tp-link", "d-link", "netgear", "mikrotik", "ubiquiti", "cisco",
         "aruba", "routerboard"),
        "Router / Access Point",
    ),
    (
        ("vmware", "virtualbox", "hyper-v", "parallels", "innotek", "qemu",
         "kvm"),
        "Maquina virtual",
    ),
    (
        ("intel", "dell", "hewlett", "hp inc", "lenovo", "asustek", "gigabyte",
         "giga-byte", "msi", "asrock", "wistron", "liteon", "ibm", "packard"),
        "PC / Laptop",
    ),
    (("amazon", "roku", "google", "nest", "philips"), "Streaming / Smart home"),
    (("sonos", "shenzhen", "tuya"), "IoT / domotica"),
    (("microsoft",), "PC / consola (Microsoft)"),
]

# Pistas por puerto abierto cuando el fabricante no basta.
_PISTAS_PUERTO = [
    ({3389, 445, 139, 135}, "PC / Servidor Windows"),
    ({22}, "Host Linux/Unix (SSH)"),
    ({80, 443, 8080, 8443}, "Servidor web"),
    ({3306, 5432, 1433, 27017, 6379, 9200}, "Servidor de base de datos"),
    ({9100, 515, 631}, "Impresora de red"),
    ({1883, 8883, 5683}, "Dispositivo IoT (MQTT/CoAP)"),
    ({554, 8554, 37777}, "Camara / DVR"),
]


def vendor_por_mac(mac):
    """Devuelve el fabricante segun el prefijo OUI de la MAC."""
    if not mac:
        return "Desconocido"
    prefijo = mac.lower()[:8]
    return OUI.get(prefijo, "Desconocido")


def adivinar_tipo(vendor, puertos_abiertos=None):
    """Infiere el tipo de dispositivo por fabricante y, si no, por puertos."""
    vendor_lower = (vendor or "").lower()
    for claves, etiqueta in _REGLAS_TIPO:
        if any(clave in vendor_lower for clave in claves):
            return etiqueta

    if puertos_abiertos:
        conjunto = set(puertos_abiertos)
        for puertos_clave, etiqueta in _PISTAS_PUERTO:
            if conjunto & puertos_clave:
                return etiqueta

    return "Desconocido"


def ttl_a_so(ttl):
    """Infiere el SO a partir del TTL inicial tipico."""
    if ttl is None:
        return "Desconocido"
    if ttl <= 64:
        return "Linux/Android/macOS"
    if ttl <= 128:
        return "Windows"
    return "Router/Red (TTL alto)"


def hostname_de_ip(ip):
    """DNS inverso. Devuelve '-' si no hay nombre registrado."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"


def identificar_host(ip, mac=None, ttl=None, puertos_abiertos=None):
    """Reune toda la informacion de identificacion de un host."""
    vendor = vendor_por_mac(mac)
    return {
        "ip": ip,
        "mac": mac or "-",
        "hostname": hostname_de_ip(ip),
        "vendor": vendor,
        "tipo_probable": adivinar_tipo(vendor, puertos_abiertos),
        "so_probable": ttl_a_so(ttl),
        "ttl": ttl,
    }
'''
_registrar_modulo("identificador", _CODIGO_IDENTIFICADOR)
setattr(_paquete, "identificador", sys.modules["identificador"])

# --- modulo: servicios ---
_CODIGO_SERVICIOS = r'''"""Deteccion de servicios y versiones (equivalente nativo a `nmap -sV`).

Hace banner grabbing especifico por protocolo usando solo sockets y ssl de
la biblioteca estandar. No es intrusivo: solo se conecta, lee el saludo del
servicio y, en el caso HTTP, pide la pagina raiz.

Devuelve estructuras uniformes:
    {
      "puerto": int,
      "servicio": str,     # familia (http, ssh, ftp, ...)
      "producto": str,     # p.ej. "OpenSSH", "Apache httpd", "nginx"
      "version": str,      # p.ej. "8.2p1", "2.4.49"  ("" si no se pudo)
      "extra": str,        # info adicional (titulo web, SO, cert, ...)
      "banner": str,       # saludo crudo recortado
    }
"""

import re
import socket
import ssl

PUERTOS_WEB = {80, 81, 591, 2082, 2095, 3000, 5000, 8000, 8008, 8080, 8081,
               8088, 8090, 8888, 9090, 9200}
PUERTOS_WEB_TLS = {443, 2083, 2096, 4443, 8443, 9443, 10443}

# Firmas: (regex sobre el banner) -> (producto, grupo_version_o_None)
_FIRMAS = [
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\w.p]+)", re.I), "OpenSSH", 1),
    (re.compile(r"SSH-[\d.]+-(.+)", re.I), "SSH", None),
    (re.compile(r"220.*?vsFTPd\s+([\d.]+)", re.I), "vsftpd", 1),
    (re.compile(r"220.*?ProFTPD\s+([\d.]+)", re.I), "ProFTPD", 1),
    (re.compile(r"220.*?FileZilla Server[^\d]*([\d.]+)", re.I), "FileZilla ftpd", 1),
    (re.compile(r"220[- ].*?FTP", re.I), "FTP", None),
    (re.compile(r"220.*?(Postfix|Exim|Sendmail|Microsoft ESMTP)", re.I), "SMTP", None),
    (re.compile(r"^\+OK.*?POP3", re.I), "POP3", None),
    (re.compile(r"\* OK.*?IMAP", re.I), "IMAP", None),
    (re.compile(r"([\d.]+)-MariaDB", re.I), "MariaDB", 1),
    (re.compile(r"\x00{0,3}([\d]+\.[\d]+\.[\d]+)\x00", re.I), "MySQL", 1),
    (re.compile(r"-ERR.*?Redis|redis_version:([\d.]+)", re.I), "Redis", 1),
    (re.compile(r"RFB (\d{3}\.\d{3})", re.I), "VNC", 1),
]


def _leer_banner(sock, n=256):
    try:
        sock.settimeout(2.0)
        return sock.recv(n).decode("latin-1", errors="replace")
    except OSError:
        return ""


def _probe_http(ip, puerto, usar_tls, timeout):
    """Peticion HTTP GET minima. Devuelve (producto, version, extra, banner)."""
    try:
        raw = socket.create_connection((ip, puerto), timeout=timeout)
    except OSError:
        return "", "", "", ""

    sock = raw
    try:
        if usar_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)

        peticion = (
            f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
            "User-Agent: mi_escanner/1.0\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(peticion.encode())
        sock.settimeout(timeout)
        datos = b""
        while len(datos) < 8192:
            try:
                trozo = sock.recv(4096)
            except OSError:
                break
            if not trozo:
                break
            datos += trozo
        texto = datos.decode("latin-1", errors="replace")
    finally:
        try:
            sock.close()
        except OSError:
            pass

    server = re.search(r"^Server:\s*(.+)$", texto, re.I | re.M)
    titulo = re.search(r"<title[^>]*>(.*?)</title>", texto, re.I | re.S)
    estado = re.search(r"HTTP/[\d.]+\s+(\d{3})", texto)

    producto, version = "", ""
    if server:
        banner_srv = server.group(1).strip()
        m = re.search(r"(Apache)(?:/([\d.]+))?", banner_srv, re.I) or \
            re.search(r"(nginx)(?:/([\d.]+))?", banner_srv, re.I) or \
            re.search(r"(Microsoft-IIS)(?:/([\d.]+))?", banner_srv, re.I) or \
            re.search(r"(lighttpd)(?:/([\d.]+))?", banner_srv, re.I)
        if m:
            producto = {"apache": "Apache httpd", "nginx": "nginx",
                        "microsoft-iis": "IIS", "lighttpd": "lighttpd"}.get(
                m.group(1).lower(), m.group(1))
            version = m.group(2) or ""
        else:
            producto = banner_srv
    else:
        producto = "HTTP"

    extra_partes = []
    if estado:
        extra_partes.append(f"HTTP {estado.group(1)}")
    if titulo:
        t = re.sub(r"\s+", " ", titulo.group(1)).strip()
        if t:
            extra_partes.append(f'titulo="{t[:60]}"')
    extra = " | ".join(extra_partes)
    banner = (server.group(0).strip() if server else "")[:120]
    return producto, version, extra, banner


def _probe_tls_cert(ip, puerto, timeout):
    """Extrae info del certificado y version TLS negociada."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, puerto), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                cert = s.getpeercert(binary_form=False) or {}
                proto = s.version()
                cn = ""
                for campo in cert.get("subject", ()):
                    for k, v in campo:
                        if k == "commonName":
                            cn = v
                venc = cert.get("notAfter", "")
                partes = [f"TLS={proto}"]
                if cn:
                    partes.append(f"CN={cn}")
                if venc:
                    partes.append(f"vence={venc}")
                return " ".join(partes)
    except (OSError, ssl.SSLError):
        return ""


def detectar_servicio(ip, puerto, timeout=2.5):
    """Detecta servicio/producto/version de un puerto TCP ya conocido abierto."""
    resultado = {
        "puerto": puerto, "servicio": "desconocido", "producto": "",
        "version": "", "extra": "", "banner": "",
    }

    # --- HTTP/HTTPS ---
    if puerto in PUERTOS_WEB or puerto in PUERTOS_WEB_TLS:
        usar_tls = puerto in PUERTOS_WEB_TLS
        producto, version, extra, banner = _probe_http(ip, puerto, usar_tls, timeout)
        resultado.update(
            servicio="https" if usar_tls else "http",
            producto=producto, version=version, extra=extra, banner=banner,
        )
        if usar_tls:
            cert = _probe_tls_cert(ip, puerto, timeout)
            if cert:
                resultado["extra"] = (resultado["extra"] + " | " + cert).strip(" |")
        return resultado

    # --- Servicios que anuncian banner al conectar ---
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            banner = _leer_banner(s)
    except OSError:
        banner = ""

    resultado["banner"] = banner.strip()[:120]
    for regex, producto, grupo in _FIRMAS:
        m = regex.search(banner)
        if m:
            resultado["producto"] = producto
            resultado["version"] = (m.group(grupo) if grupo else "") or ""
            resultado["servicio"] = producto.split()[0].lower()
            return resultado

    # Si hubo banner pero no coincidio ninguna firma, lo dejamos crudo.
    if banner.strip():
        resultado["producto"] = banner.strip().splitlines()[0][:40]
    return resultado


def detectar_varios(ip, puertos, timeout=2.5):
    """Detecta servicios para una lista de puertos abiertos (secuencial)."""
    return [detectar_servicio(ip, p, timeout) for p in puertos]
'''
_registrar_modulo("servicios", _CODIGO_SERVICIOS)
setattr(_paquete, "servicios", sys.modules["servicios"])

# --- modulo: vulnerabilidades ---
_CODIGO_VULNERABILIDADES = r'''"""Analizador de vulnerabilidades (equivalente nativo a `nmap -sC --script vuln`).

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
'''
_registrar_modulo("vulnerabilidades", _CODIGO_VULNERABILIDADES)
setattr(_paquete, "vulnerabilidades", sys.modules["vulnerabilidades"])

# --- modulo: privesc ---
_CODIGO_PRIVESC = r'''"""Auditor local de escalada de privilegios (estilo WinPEAS / LinPEAS).

Se ejecuta en la MAQUINA LOCAL que administras y reporta configuraciones
debiles que un atacante podria aprovechar para elevar privilegios. NO explota
nada: solo lee el estado del sistema y sugiere remediaciones.

Pensado para auditoria defensiva del propio equipo o de hosts para los que
tengas autorizacion explicita.

Cada hallazgo:
    {"sev": "Critica|Alta|Media|Baja|Info",
     "categoria": str, "detalle": str, "recomendacion": str,
     "tecnica": str, "referencia": str}
Los campos 'tecnica' y 'referencia' son educativos: nombran el vector y a donde
ir a aprender/remediar (util para quien empieza).
"""

import ctypes
import getpass
import os
import platform
import re
import subprocess
import tempfile

ES_WINDOWS = platform.system().lower().startswith("win")
_ORDEN_SEV = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Info": 4}


def _h(sev, categoria, detalle, recomendacion="", tecnica="", referencia=""):
    return {"sev": sev, "categoria": categoria, "detalle": detalle,
            "recomendacion": recomendacion, "tecnica": tecnica,
            "referencia": referencia}


def _run(cmd, shell=False, timeout=20):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout + r.stderr
    except (subprocess.SubprocessError, OSError):
        return ""


def _puedo_escribir(carpeta):
    """Prueba de escritura REAL (crea y borra un temporal).

    En Windows os.access(W_OK) ignora las ACLs y da falsos positivos; por eso
    intentamos crear un archivo de verdad y capturamos el fallo de permisos.
    """
    if not os.path.isdir(carpeta):
        return False
    try:
        with tempfile.NamedTemporaryFile(dir=carpeta, prefix=".perm_test_",
                                         delete=True):
            return True
    except (OSError, PermissionError):
        return False


# --------------------------------------------------------------------------- #
#  Contexto comun
# --------------------------------------------------------------------------- #
def _es_admin():
    try:
        if ES_WINDOWS:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def _contexto():
    h = []
    usuario = getpass.getuser()
    admin = _es_admin()
    h.append(_h("Info", "Contexto",
               f"Usuario: {usuario} | Admin/root: {'SI' if admin else 'NO'} | "
               f"SO: {platform.platform()}",
               "Ejecuta la auditoria como usuario normal para ver que veria un atacante."))
    return h


# --------------------------------------------------------------------------- #
#  Windows
# --------------------------------------------------------------------------- #
def _win_always_install_elevated():
    h = []
    for raiz in ("HKLM", "HKCU"):
        out = _run(["reg", "query",
                    rf"{raiz}\SOFTWARE\Policies\Microsoft\Windows\Installer",
                    "/v", "AlwaysInstallElevated"])
        if re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1", out):
            h.append(_h("Critica", "AlwaysInstallElevated",
                        f"{raiz} tiene AlwaysInstallElevated=1",
                        "Si HKLM y HKCU estan a 1, cualquier .msi corre como SYSTEM. "
                        "Poner ambos a 0 por GPO."))
    return h


def _powershell(comando):
    """Ejecuta un comando de PowerShell (presente en todo Windows moderno)."""
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 comando])


def _win_servicios_sin_comillas():
    """Rutas de servicio sin comillas y con espacios -> secuestro de binario.

    Usa CIM (Get-CimInstance) porque wmic ya no existe en Windows 11 recientes.
    """
    h = []
    out = _powershell(
        "Get-CimInstance Win32_Service | "
        "Where-Object { $_.PathName } | "
        "ForEach-Object { $_.Name + '|' + $_.PathName }"
    )
    for linea in out.splitlines():
        if "|" not in linea:
            continue
        nombre, pathname = linea.split("|", 1)
        pathname = pathname.strip()
        # Nos quedamos con el ejecutable (antes de sus argumentos).
        if pathname.startswith('"'):
            continue  # ya esta entre comillas -> seguro
        exe = pathname.split(".exe", 1)[0] + ".exe" if ".exe" in pathname.lower() else pathname
        if " " in exe and ":\\" in exe:
            h.append(_h("Alta", "Servicio con ruta sin comillas",
                        f"{nombre.strip()}: {pathname[:120]}",
                        "Encerrar la ruta del servicio entre comillas en el registro "
                        "(ImagePath). Riesgo de secuestro de binario."))
    return h[:10]


def _win_autologon():
    h = []
    out = _run(["reg", "query",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"])
    if re.search(r"DefaultPassword\s+REG_SZ\s+\S", out):
        h.append(_h("Critica", "Credenciales de autologon en registro",
                    "DefaultPassword presente en Winlogon",
                    "Eliminar DefaultPassword; usar autologon seguro o deshabilitarlo."))
    return h


def _win_unattend():
    h = []
    candidatos = [
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\Autounattend.xml",
        r"C:\Windows\System32\Sysprep\unattend.xml",
    ]
    for ruta in candidatos:
        if os.path.isfile(ruta):
            h.append(_h("Alta", "Archivo unattend/sysprep presente", ruta,
                        "Puede contener contrasenas en texto/base64. Revisar y borrar."))
    return h


def _win_path_escribible():
    h = []
    for carpeta in os.environ.get("PATH", "").split(os.pathsep):
        carpeta = carpeta.strip('"')
        if carpeta and _puedo_escribir(carpeta):
            h.append(_h("Media", "Carpeta del PATH escribible por el usuario",
                        carpeta,
                        "Un atacante podria plantar binarios (DLL/exe hijacking). "
                        "Restringir permisos de la carpeta."))
    return h[:10]


def _win_parches():
    h = []
    out = _powershell("Get-HotFix | Select-Object -ExpandProperty HotFixID")
    hotfixes = re.findall(r"KB\d+", out)
    ultimo = _powershell(
        "(Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1).InstalledOn"
    ).strip()
    detalle = f"{len(hotfixes)} hotfixes instalados"
    if ultimo:
        detalle += f" | ultimo: {ultimo}"
    h.append(_h("Info", "Parches instalados", detalle,
               "Comparar con el ultimo Patch Tuesday; faltantes = posibles CVE locales."))
    return h


def _win_privilegios_token():
    """Privilegios del token actual abusables para suplantar a SYSTEM."""
    h = []
    out = _run(["whoami", "/priv"])
    abusables = {
        "SeImpersonatePrivilege": "familia Potato (JuicyPotato/PrintSpoofer)",
        "SeAssignPrimaryTokenPrivilege": "suplantacion de token primario",
        "SeBackupPrivilege": "lectura de archivos protegidos (SAM/SYSTEM)",
        "SeRestorePrivilege": "escritura de archivos protegidos",
        "SeDebugPrivilege": "acceso a memoria de procesos de SYSTEM",
        "SeTakeOwnershipPrivilege": "tomar propiedad de objetos protegidos",
    }
    for priv, tecnica in abusables.items():
        # Habilitado o disponible (no "Disabled" sin mas no basta; se reporta si aparece).
        if priv in out:
            estado = "Enabled" if re.search(priv + r".*Enabled", out) else "presente"
            h.append(_h("Alta", "Privilegio de token abusable",
                        f"{priv} ({estado})",
                        "Revocar el privilegio al usuario si no es necesario.",
                        tecnica=tecnica,
                        referencia="https://book.hacktricks.xyz (Windows token privileges)"))
    return h


def _win_credenciales_guardadas():
    """Credenciales almacenadas que pueden reutilizarse (cmdkey)."""
    h = []
    out = _run(["cmdkey", "/list"])
    objetivos = re.findall(r"Target:\s*(.+)", out)
    if objetivos:
        h.append(_h("Media", "Credenciales guardadas en el Administrador",
                    f"{len(objetivos)} entradas (p.ej. {objetivos[0].strip()[:50]})",
                    "Revisar y eliminar credenciales guardadas innecesarias.",
                    tecnica="runas /savecred reutiliza estas credenciales",
                    referencia="cmdkey / runas (Stored Credentials)"))
    return h


def _win_autoruns_escribibles():
    """Entradas de arranque cuyo ejecutable es escribible por el usuario."""
    h = []
    claves = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ]
    for clave in claves:
        out = _run(["reg", "query", clave])
        for m in re.finditer(r"REG_[A-Z_]+\s+(.+)", out):
            ruta = m.group(1).strip().strip('"')
            exe = ruta.split(".exe")[0] + ".exe" if ".exe" in ruta.lower() else ruta
            carpeta = os.path.dirname(exe)
            if carpeta and _puedo_escribir(carpeta):
                h.append(_h("Alta", "Autorun con binario/carpeta escribible",
                            f"{clave.split(chr(92))[0]}: {exe[:80]}",
                            "Restringir permisos del ejecutable de arranque.",
                            tecnica="reemplazo de binario de autorun",
                            referencia="Autorun hijacking"))
    return h[:10]


def _win_tareas_escribibles():
    """Tareas programadas cuyo binario esta en carpeta escribible."""
    h = []
    out = _powershell(
        "Get-ScheduledTask | ForEach-Object { "
        "$_.TaskName + '|' + ($_.Actions.Execute -join ',') } 2>$null"
    )
    vistos = set()
    for linea in out.splitlines():
        if "|" not in linea:
            continue
        nombre, ejec = linea.split("|", 1)
        ejec = ejec.strip().strip('"')
        if not ejec or ejec in vistos:
            continue
        vistos.add(ejec)
        carpeta = os.path.dirname(ejec) if "\\" in ejec else ""
        if carpeta and _puedo_escribir(carpeta):
            h.append(_h("Alta", "Tarea programada con binario escribible",
                        f"{nombre.strip()[:40]}: {ejec[:70]}",
                        "Mover el binario a una ruta protegida.",
                        tecnica="reemplazo de binario de tarea programada",
                        referencia="Scheduled task abuse"))
    return h[:10]


def _auditar_windows():
    h = []
    for fn in (_win_privilegios_token, _win_always_install_elevated,
               _win_servicios_sin_comillas, _win_autologon, _win_unattend,
               _win_credenciales_guardadas, _win_autoruns_escribibles,
               _win_tareas_escribibles, _win_path_escribible, _win_parches):
        try:
            h += fn()
        except Exception:
            pass
    return h


# --------------------------------------------------------------------------- #
#  Linux
# --------------------------------------------------------------------------- #
def _lin_suid():
    h = []
    out = _run("find / -perm -4000 -type f 2>/dev/null", shell=True, timeout=40)
    binarios = [l for l in out.splitlines() if l.strip()]
    # SUID conocidos por ser abusables (GTFOBins).
    peligrosos = ("nmap", "vim", "find", "bash", "more", "less", "nano", "cp",
                  "python", "perl", "awk", "env", "tar", "zip", "docker")
    for b in binarios:
        base = os.path.basename(b)
        if any(p in base for p in peligrosos):
            h.append(_h("Alta", "Binario SUID potencialmente abusable", b,
                        f"'{base}' con SUID suele permitir shell root (ver GTFOBins). "
                        "Quitar el bit SUID si no es imprescindible."))
    if binarios and not h:
        h.append(_h("Info", "Binarios SUID",
                   f"{len(binarios)} binarios SUID (ninguno en lista negra comun)",
                   "Revisar manualmente contra GTFOBins."))
    return h[:15]


def _lin_sudo():
    h = []
    out = _run("sudo -n -l 2>/dev/null", shell=True)
    if "NOPASSWD" in out:
        for linea in out.splitlines():
            if "NOPASSWD" in linea:
                h.append(_h("Alta", "Regla sudo NOPASSWD", linea.strip()[:160],
                            "Comandos ejecutables como root sin contrasena. Revisar GTFOBins."))
    return h


def _lin_escribibles():
    h = []
    # /etc/passwd escribible = root trivial.
    if os.path.isfile("/etc/passwd") and os.access("/etc/passwd", os.W_OK):
        h.append(_h("Critica", "/etc/passwd escribible",
                    "El usuario actual puede escribir /etc/passwd",
                    "Permite anadir un usuario root. Corregir permisos (644)."))
    if os.path.isfile("/etc/shadow") and os.access("/etc/shadow", os.R_OK):
        h.append(_h("Critica", "/etc/shadow legible",
                    "El usuario actual puede leer /etc/shadow",
                    "Hashes de contrasenas expuestos. Corregir permisos (640 root:shadow)."))
    return h


def _lin_cron():
    h = []
    for ruta in ("/etc/crontab", "/etc/cron.d"):
        if os.path.exists(ruta) and os.access(ruta, os.W_OK):
            h.append(_h("Alta", "Cron escribible", ruta,
                        "Tareas programadas modificables -> ejecucion como root."))
    return h


def _lin_kernel():
    h = []
    out = _run("uname -r", shell=True).strip()
    if out:
        h.append(_h("Info", "Version de kernel", out,
                   "Comparar con linux-exploit-suggester para CVE locales conocidos."))
    return h


def _lin_path_escribible():
    h = []
    for carpeta in os.environ.get("PATH", "").split(os.pathsep):
        if carpeta and _puedo_escribir(carpeta):
            h.append(_h("Media", "Carpeta del PATH escribible", carpeta,
                        "Riesgo de secuestro de binarios. Restringir permisos."))
    return h[:10]


def _lin_capabilities():
    """Capabilities de archivo abusables (equivalente moderno a SUID)."""
    h = []
    out = _run("getcap -r / 2>/dev/null", shell=True, timeout=40)
    abusables = ("cap_setuid", "cap_setgid", "cap_dac_override",
                 "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace")
    for linea in out.splitlines():
        ll = linea.lower()
        if any(c in ll for c in abusables):
            h.append(_h("Alta", "Capability de archivo abusable", linea.strip()[:160],
                        "Quitar la capability si no es imprescindible (setcap -r).",
                        tecnica="abuso de capabilities (ver GTFOBins)",
                        referencia="getcap / GTFOBins (capabilities)"))
    return h[:10]


def _lin_grupos_peligrosos():
    """Pertenencia a grupos que dan via directa a root (docker, lxd, disk...)."""
    h = []
    out = _run("id", shell=True)
    for grupo, nota in [
        ("docker", "montar / como contenedor -> root"),
        ("lxd", "crear contenedor privilegiado -> root"),
        ("disk", "leer/escribir dispositivos de bloque -> leer /etc/shadow"),
        ("sudo", "puede usar sudo (revisar reglas)"),
        ("adm", "lectura de logs sensibles"),
    ]:
        if re.search(r"\b" + grupo + r"\b", out):
            sev = "Alta" if grupo in ("docker", "lxd", "disk") else "Media"
            h.append(_h(sev, f"Miembro del grupo '{grupo}'", out.strip()[:120],
                        "Quitar al usuario del grupo si no lo necesita.",
                        tecnica=nota,
                        referencia="Linux privesc por grupos (HackTricks)"))
    return h


def _lin_nfs():
    """Exportaciones NFS con no_root_squash (escritura SUID como root)."""
    h = []
    if os.path.isfile("/etc/exports"):
        try:
            with open("/etc/exports", "r", errors="replace") as f:
                contenido = f.read()
        except OSError:
            contenido = ""
        for linea in contenido.splitlines():
            if "no_root_squash" in linea and not linea.strip().startswith("#"):
                h.append(_h("Alta", "NFS con no_root_squash", linea.strip()[:160],
                            "Usar root_squash en los exports NFS.",
                            tecnica="montar el export y colocar un binario SUID root",
                            referencia="NFS no_root_squash privesc"))
    return h


def _auditar_linux():
    h = []
    for fn in (_lin_escribibles, _lin_sudo, _lin_suid, _lin_capabilities,
               _lin_grupos_peligrosos, _lin_nfs, _lin_cron,
               _lin_path_escribible, _lin_kernel):
        try:
            h += fn()
        except Exception:
            pass
    return h


# --------------------------------------------------------------------------- #
#  Orquestador
# --------------------------------------------------------------------------- #
def auditar_local():
    """Ejecuta la auditoria segun el SO y devuelve hallazgos ordenados."""
    h = _contexto()
    h += _auditar_windows() if ES_WINDOWS else _auditar_linux()
    h.sort(key=lambda x: _ORDEN_SEV.get(x["sev"], 99))
    return h
'''
_registrar_modulo("privesc", _CODIGO_PRIVESC)
setattr(_paquete, "privesc", sys.modules["privesc"])

# --- modulo: escaner_web ---
_CODIGO_ESCANER_WEB = r'''"""Auditor web nativo (estilo Nikto, no Burp/Repeater).

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
'''
_registrar_modulo("escaner_web", _CODIGO_ESCANER_WEB)
setattr(_paquete, "escaner_web", sys.modules["escaner_web"])

# --- modulo: password_audit ---
_CODIGO_PASSWORD_AUDIT = r'''"""Auditor de robustez de contrasenas y politica (alternativa defensiva a John).

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
'''
_registrar_modulo("password_audit", _CODIGO_PASSWORD_AUDIT)
setattr(_paquete, "password_audit", sys.modules["password_audit"])

# --- modulo: cracker ---
_CODIGO_CRACKER = r'''"""Auditoria de hashes por diccionario / fuerza bruta (estilo John the Ripper).

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
'''
_registrar_modulo("cracker", _CODIGO_CRACKER)
setattr(_paquete, "cracker", sys.modules["cracker"])

# --- modulo: recon_local ---
_CODIGO_RECON_LOCAL = r'''"""Monitor local de red (alternativa defensiva a Wireshark/Aircrack).

Solo lectura: no captura paquetes ni inyecta trafico (eso exigiria root/Npcap).
  - conexiones_activas(): conexiones establecidas y puertos en escucha, con PID.
  - redes_wifi(): redes WiFi visibles y su cifrado (marca WEP/abiertas).
"""

import re

from modulos import sistema


def conexiones_activas():
    """Lista conexiones y puertos en escucha. Devuelve lista de dicts."""
    filas = []
    if sistema.ES_WINDOWS:
        out = sistema.run(["netstat", "-ano"])
        for linea in out.splitlines():
            partes = linea.split()
            if len(partes) >= 4 and partes[0] in ("TCP", "UDP"):
                proto, local, remoto = partes[0], partes[1], partes[2]
                estado = partes[3] if proto == "TCP" and len(partes) >= 5 else "-"
                pid = partes[-1]
                filas.append({"proto": proto, "local": local, "remoto": remoto,
                              "estado": estado, "pid": pid})
    else:
        out = sistema.run("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null",
                          shell=True)
        for linea in out.splitlines():
            if "ESTAB" in linea or "LISTEN" in linea:
                partes = linea.split()
                filas.append({"proto": partes[0] if partes else "-",
                              "local": partes[4] if len(partes) > 4 else "-",
                              "remoto": partes[5] if len(partes) > 5 else "-",
                              "estado": "LISTEN" if "LISTEN" in linea else "ESTAB",
                              "pid": partes[-1][:40] if partes else "-"})
    return filas


def conexiones_destacadas(filas):
    """Marca escuchas expuestas (0.0.0.0/::) como puntos de atencion."""
    alertas = []
    for f in filas:
        if f["estado"] in ("LISTENING", "LISTEN"):
            if f["local"].startswith(("0.0.0.0", "[::]", "::")):
                alertas.append(f)
    return alertas


def redes_wifi():
    """Lista redes WiFi visibles y su cifrado. Devuelve lista de dicts."""
    redes = []
    if sistema.ES_WINDOWS:
        out = sistema.run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        ssid, cifrado, auth = None, None, None
        for linea in out.splitlines():
            l = linea.strip()
            m = re.match(r"SSID\s+\d+\s*:\s*(.*)", l)
            if m:
                if ssid is not None:
                    redes.append({"ssid": ssid or "(oculta)",
                                  "auth": auth or "?", "cifrado": cifrado or "?"})
                ssid, cifrado, auth = m.group(1).strip(), None, None
            elif l.lower().startswith("authentication") or l.lower().startswith("autentic"):
                auth = l.split(":", 1)[1].strip()
            elif l.lower().startswith("encryption") or l.lower().startswith("cifrado"):
                cifrado = l.split(":", 1)[1].strip()
        if ssid is not None:
            redes.append({"ssid": ssid or "(oculta)", "auth": auth or "?",
                          "cifrado": cifrado or "?"})
    else:
        out = sistema.run("nmcli -t -f SSID,SECURITY dev wifi 2>/dev/null",
                          shell=True)
        for linea in out.splitlines():
            if ":" in linea:
                nombre, seg = linea.rsplit(":", 1)
                redes.append({"ssid": nombre or "(oculta)", "auth": seg or "?",
                              "cifrado": seg or "?"})
    return redes


def wifi_inseguras(redes):
    """Devuelve las redes con cifrado debil (abierto/WEP)."""
    debiles = []
    for r in redes:
        texto = (r.get("auth", "") + " " + r.get("cifrado", "")).lower()
        if "wep" in texto or "open" in texto or "abierta" in texto or texto.strip() in ("? ?", "?"):
            if "wpa" not in texto:
                debiles.append(r)
    return debiles
'''
_registrar_modulo("recon_local", _CODIGO_RECON_LOCAL)
setattr(_paquete, "recon_local", sys.modules["recon_local"])

# --- modulo: reporte ---
_CODIGO_REPORTE = r'''"""Generador de reportes (estilo Nessus/OpenVAS).

Consolida los resultados de una sesion en dos archivos sin dependencias:
  - wraith_report.json : datos crudos (para automatizar o reprocesar).
  - wraith_report.html : informe autonomo con CSS inline y severidades.
"""

import datetime
import html
import json
import os

from modulos import sistema

# Paleta neon (sobre fondo oscuro tipo Mr. Robot).
_COLOR_SEV = {
    "Critica": "#ff2d55", "Alta": "#ff7b00", "Media": "#ffd60a",
    "Baja": "#00e5ff", "Info": "#4caf7d",
}
_ORDEN_SEV = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Info": 4}


def _badge(sev):
    color = _COLOR_SEV.get(sev, "#4caf7d")
    return (f'<span class="badge" style="color:{color};border-color:{color};'
            f'box-shadow:0 0 8px {color}66,inset 0 0 6px {color}22">'
            f'{html.escape(sev)}</span>')


def _tabla(cabeceras, filas):
    if not filas:
        return "<p class='vacio'>// sin datos</p>"
    th = "".join(f"<th>{html.escape(c)}</th>" for c in cabeceras)
    trs = []
    for fila in filas:
        tds = "".join(f"<td>{c}</td>" for c in fila)  # celdas ya escapadas
        trs.append(f"<tr>{tds}</tr>")
    return (f"<div class='tabla-wrap'><table><thead><tr>{th}</tr></thead><tbody>"
            + "".join(trs) + "</tbody></table></div>")


def _resumen_severidades(vulns, privesc):
    conteo = {s: 0 for s in _ORDEN_SEV}
    for h in list(vulns) + list(privesc):
        conteo[h.get("sev", "Info")] = conteo.get(h.get("sev", "Info"), 0) + 1
    tarjetas = []
    for sev in sorted(conteo, key=lambda s: _ORDEN_SEV.get(s, 9)):
        color = _COLOR_SEV.get(sev, "#4caf7d")
        tarjetas.append(
            f'<div class="card" style="border-color:{color};'
            f'box-shadow:0 0 14px {color}44,inset 0 0 10px {color}11">'
            f'<div class="card-n" style="color:{color};text-shadow:0 0 12px {color}">'
            f'{conteo[sev]}</div>'
            f'<div class="card-l">{html.escape(sev)}</div></div>')
    return '<div class="cards">' + "".join(tarjetas) + "</div>"


def _html(datos):
    e = html.escape
    meta = datos.get("meta", {})
    hosts = datos.get("hosts", [])
    servicios = datos.get("servicios", [])
    vulns = sorted(datos.get("vulnerabilidades", []),
                   key=lambda h: _ORDEN_SEV.get(h.get("sev", "Info"), 9))
    privesc = sorted(datos.get("privesc", []),
                     key=lambda h: _ORDEN_SEV.get(h.get("sev", "Info"), 9))
    conexiones = datos.get("conexiones", [])
    wifi = datos.get("wifi", [])

    secciones = []

    secciones.append(_resumen_severidades(vulns, privesc))

    if hosts:
        filas = [[e(str(h.get(k, "-"))) for k in
                  ("ip", "mac", "hostname", "vendor", "tipo_probable", "so_probable")]
                 for h in hosts]
        secciones.append("<h2>Hosts descubiertos</h2>" + _tabla(
            ["IP", "MAC", "Hostname", "Fabricante", "Tipo", "SO"], filas))

    if servicios:
        filas = [[e(str(s.get(k, "-"))) for k in
                  ("ip", "puerto", "servicio", "producto", "version", "extra")]
                 for s in servicios]
        secciones.append("<h2>Servicios detectados</h2>" + _tabla(
            ["IP", "Puerto", "Servicio", "Producto", "Version", "Info"], filas))

    if vulns:
        filas = []
        for h in vulns:
            filas.append([
                _badge(h.get("sev", "Info")),
                e(str(h.get("puerto", "-"))),
                e(str(h.get("cve", "-"))),
                e(str(h.get("titulo", ""))),
                e(str(h.get("remediacion", ""))),
            ])
        secciones.append("<h2>Vulnerabilidades y hallazgos</h2>" + _tabla(
            ["Sev", "Puerto", "CVE/Ref", "Hallazgo", "Remediacion"], filas))

    if privesc:
        filas = []
        for h in privesc:
            ref = h.get("referencia", "")
            tec = h.get("tecnica", "")
            extra = (f"{e(tec)}" + (f" — {e(ref)}" if ref else "")) if tec else e(ref)
            filas.append([
                _badge(h.get("sev", "Info")),
                e(str(h.get("categoria", ""))),
                e(str(h.get("detalle", ""))),
                e(str(h.get("recomendacion", ""))) + (f"<br><small>{extra}</small>" if extra else ""),
            ])
        secciones.append("<h2>Escalada de privilegios (local)</h2>" + _tabla(
            ["Sev", "Categoria", "Detalle", "Remediacion / Tecnica"], filas))

    if conexiones:
        filas = [[e(str(c.get(k, "-"))) for k in
                  ("proto", "local", "remoto", "estado", "pid")] for c in conexiones]
        secciones.append("<h2>Conexiones / puertos en escucha</h2>" + _tabla(
            ["Proto", "Local", "Remoto", "Estado", "PID"], filas))

    if wifi:
        filas = [[e(str(w.get(k, "-"))) for k in ("ssid", "auth", "cifrado")]
                 for w in wifi]
        secciones.append("<h2>Redes WiFi visibles</h2>" + _tabla(
            ["SSID", "Autenticacion", "Cifrado"], filas))

    hashes = datos.get("hashes", [])
    if hashes:
        filas = []
        for x in hashes:
            crack = x.get("estado") == "CRACKEADO"
            estado = (_badge("Critica") if crack else _badge("Info")).replace(
                ">Critica<", ">CRACKEADO<").replace(">Info<", ">pendiente<")
            filas.append([
                e(str(x.get("usuario", "-"))), e(str(x.get("tipo", "-"))),
                estado, e(str(x.get("password", "-")))])
        secciones.append("<h2>Credenciales debiles</h2>" + _tabla(
            ["Usuario", "Tipo", "Estado", "Password recuperada"], filas))

    estilo = """
    <style>
      :root{--bg:#060a06;--panel:#0b120b;--green:#00ff41;--green2:#19c35c;
            --dim:#0f2a16;--txt:#c8f7d2;--muted:#5f8f6f}
      *{box-sizing:border-box}
      body{font-family:'Cascadia Code','JetBrains Mono','Fira Code',Consolas,
           monospace;margin:0;color:var(--txt);
           background:var(--bg);
           background-image:
             linear-gradient(rgba(0,255,65,.04) 1px,transparent 1px),
             linear-gradient(90deg,rgba(0,255,65,.04) 1px,transparent 1px),
             radial-gradient(ellipse at top,rgba(0,255,65,.07),transparent 60%);
           background-size:32px 32px,32px 32px,100% 100%;
           line-height:1.5}
      /* scanlines sutiles */
      body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9;
           background:repeating-linear-gradient(transparent 0 2px,rgba(0,0,0,.18) 3px);
           opacity:.35;mix-blend-mode:overlay}
      .wrap{max-width:1180px;margin:28px auto;padding:0 18px;position:relative;z-index:1}
      .term{border:1px solid var(--dim);border-radius:10px;background:rgba(5,12,6,.85);
            box-shadow:0 0 30px rgba(0,255,65,.08);overflow:hidden}
      .bar{background:#0a140a;border-bottom:1px solid var(--dim);padding:8px 14px;
           display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted)}
      .dot{width:11px;height:11px;border-radius:50%;display:inline-block}
      .bar .t{margin-left:10px;letter-spacing:1px}
      .pad{padding:22px 26px}
      h1{color:var(--green);margin:0;font-size:30px;letter-spacing:3px;
         text-shadow:0 0 14px rgba(0,255,65,.6)}
      h1 .cur{animation:blink 1s steps(1) infinite}
      @keyframes blink{50%{opacity:0}}
      h2{color:var(--green);margin:34px 0 6px;font-size:16px;letter-spacing:1px;
         text-transform:uppercase;border-left:3px solid var(--green);padding-left:10px;
         text-shadow:0 0 8px rgba(0,255,65,.4)}
      h2::before{content:'> ';color:var(--green2)}
      .meta{color:var(--muted);font-size:12.5px;margin:8px 0}
      .meta b{color:var(--green2)}
      .cards{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
      .card{flex:1;min-width:96px;background:var(--panel);border:1px solid;
            border-radius:8px;padding:14px;text-align:center}
      .card-n{font-size:30px;font-weight:700;font-family:inherit}
      .card-l{font-size:11px;color:var(--muted);text-transform:uppercase;
              letter-spacing:2px;margin-top:2px}
      .tabla-wrap{overflow-x:auto;border:1px solid var(--dim);border-radius:8px;
                  margin-top:6px}
      table{width:100%;border-collapse:collapse;font-size:12.5px;min-width:620px}
      th{background:#0a160c;color:var(--green);text-align:left;padding:9px 11px;
         text-transform:uppercase;letter-spacing:1px;font-size:11px;
         border-bottom:1px solid var(--green2)}
      td{padding:8px 11px;border-bottom:1px solid rgba(25,195,92,.12);
         vertical-align:top;color:var(--txt)}
      tbody tr:hover td{background:rgba(0,255,65,.06)}
      small{color:var(--muted)}
      .badge{padding:2px 9px;border:1px solid;border-radius:4px;font-size:11px;
             font-weight:700;letter-spacing:1px;background:rgba(0,0,0,.3)}
      .vacio{color:var(--muted);font-size:12px}
      .foot{color:var(--muted);font-size:11.5px;margin-top:26px;
            border-top:1px solid var(--dim);padding-top:12px}
    </style>"""

    logo = ("WRAITH<span class='cur'>_</span>")
    cab = (
        "<div class='term'>"
        "<div class='bar'>"
        "<span class='dot' style='background:#ff5f56'></span>"
        "<span class='dot' style='background:#ffbd2e'></span>"
        "<span class='dot' style='background:#27c93f'></span>"
        "<span class='t'>wraith@report — security assessment</span></div>"
        f"<div class='pad'><h1>{logo}</h1>"
        f"<p class='meta'>// generado: <b>{e(meta.get('generado',''))}</b> · "
        f"sistema: <b>{e(meta.get('so',''))}</b> · "
        f"objetivo: <b>{e(meta.get('objetivo','-'))}</b></p>"
        "<p class='meta'>// wraith v3.0 · security assessment report</p>")

    cuerpo = "".join(secciones)
    foot = ("<p class='foot'>// authorized use only · "
            "verificar manualmente los hallazgos marcados como 'posible'"
            "</p></div></div>")

    return (f"<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>WRAITH // report</title>{estilo}</head>"
            f"<body><div class='wrap'>{cab}{cuerpo}{foot}</body></html>")


def generar(datos, ruta_base=None):
    """Escribe wraith_report.json y wraith_report.html. Devuelve (json, html)."""
    datos.setdefault("meta", {})
    datos["meta"].setdefault(
        "generado", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    datos["meta"].setdefault("so", sistema.so_actual())

    carpeta = ruta_base or os.getcwd()
    ruta_json = os.path.join(carpeta, "wraith_report.json")
    ruta_html = os.path.join(carpeta, "wraith_report.html")

    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    with open(ruta_html, "w", encoding="utf-8") as f:
        f.write(_html(datos))
    return ruta_json, ruta_html
'''
_registrar_modulo("reporte", _CODIGO_REPORTE)
setattr(_paquete, "reporte", sys.modules["reporte"])

# --- cuerpo principal (main.py) ---
#!/usr/bin/env python3
"""WRAITH - Network Reconnaissance & Vulnerability Suite.

Descubrimiento de red, escaneo de puertos, deteccion de servicios/versiones,
analisis de vulnerabilidades y auditoria local de escalada de privilegios.
Multiplataforma (Windows y Linux).

Uso etico: ejecutalo solo contra redes y hosts que te pertenezcan o para
los que tengas autorizacion explicita de analisis.
"""

import os
import socket
import sys

# (imports de modulos resueltos en memoria)
red = sys.modules['red']
escaner_local = sys.modules['escaner_local']
escaner_externo = sys.modules['escaner_externo']
identificador = sys.modules['identificador']
servicios = sys.modules['servicios']
vulnerabilidades = sys.modules['vulnerabilidades']
privesc = sys.modules['privesc']
sistema = sys.modules['sistema']
escaner_web = sys.modules['escaner_web']
password_audit = sys.modules['password_audit']
recon_local = sys.modules['recon_local']
reporte = sys.modules['reporte']
cracker = sys.modules['cracker']

# Acumulador de resultados de la sesion (alimenta el reporte HTML/JSON).
SESION = {"meta": {}, "hosts": [], "servicios": [], "vulnerabilidades": [],
          "privesc": [], "conexiones": [], "wifi": [], "hashes": []}


# --------------------------------------------------------------------------- #
#  Estetica: consola "Mr. Robot" (verde fosforo + truecolor + box-drawing)
# --------------------------------------------------------------------------- #
def _preparar_consola():
    """Habilita secuencias ANSI y UTF-8 (para colores y box-drawing)."""
    ansi = True
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)   # VT para stdout
            k.SetConsoleOutputCP(65001)                # consola en UTF-8
        except Exception:
            ansi = False
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(encoding="utf-8")
        except Exception:
            pass
    return ansi


_COLOR = _preparar_consola()


def _rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m" if _COLOR else ""


class C:
    RESET = "\033[0m" if _COLOR else ""
    BOLD = "\033[1m" if _COLOR else ""
    DIM = "\033[2m" if _COLOR else ""
    # Paleta fosforo (matrix / Mr. Robot)
    VERDE = _rgb(0, 255, 65)      # verde neon principal
    VERDE2 = _rgb(0, 150, 55)     # verde apagado (bordes)
    VERDE3 = _rgb(0, 90, 35)      # verde muy apagado
    BLANCO = _rgb(200, 255, 205)  # casi blanco verdoso
    ROJO = _rgb(255, 60, 60)
    AMAR = _rgb(255, 176, 0)
    CIAN = _rgb(0, 229, 255)
    GRIS = _rgb(110, 120, 110)


def _c(texto, color):
    return f"{color}{texto}{C.RESET}"


_COLOR_SEV = {
    "Critica": C.BOLD + C.ROJO,
    "Alta": C.ROJO,
    "Media": C.AMAR,
    "Baja": C.CIAN,
    "Info": C.GRIS,
}


def _sev(sev):
    return f"{_COLOR_SEV.get(sev, '')}{sev:<9}{C.RESET}"


def _titulo(texto):
    """Encabezado de seccion estilo prompt: '> [ TEXTO ]'."""
    print(f"\n{C.VERDE2}>{C.RESET} {C.BOLD}{C.VERDE}[ {texto.upper()} ]{C.RESET}")


def _tabla(cabeceras, anchos, filas, color_fila=None):
    """Dibuja una tabla enmarcada con box-drawing. color_fila(fila, i)->ANSI."""
    b = C.VERDE2
    top = "┌" + "┬".join("─" * (a + 2) for a in anchos) + "┐"
    sep = "├" + "┼".join("─" * (a + 2) for a in anchos) + "┤"
    bot = "└" + "┴".join("─" * (a + 2) for a in anchos) + "┘"
    vsep = _c(" │ ", b)
    print(_c(top, b))
    cab = vsep.join(f"{C.BOLD}{C.VERDE}{str(h)[:a]:<{a}}{C.RESET}"
                    for h, a in zip(cabeceras, anchos))
    print(_c("│ ", b) + cab + _c(" │", b))
    print(_c(sep, b))
    for i, fila in enumerate(filas):
        col = (color_fila(fila, i) if color_fila else C.BLANCO)
        celdas = vsep.join(f"{col}{str(v)[:a]:<{a}}{C.RESET}"
                           for v, a in zip(fila, anchos))
        print(_c("│ ", b) + celdas + _c(" │", b))
    print(_c(bot, b))


def _color_sev_fila(fila, i=0):
    """Color de fila segun la primera celda (severidad)."""
    return _COLOR_SEV.get(str(fila[0]), C.BLANCO)


def _barra_estado():
    """Linea de estado tipo consola de operador."""
    import datetime
    host = socket.gethostname()
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    izq = f"{C.VERDE2}operador@{C.VERDE}{host}{C.RESET}"
    med = f"{C.VERDE2}sistema:{C.RESET}{C.BLANCO}{sistema.so_actual()}{C.RESET}"
    der = f"{C.VERDE2}{ahora}{C.RESET}"
    print(f"{C.VERDE3}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄{C.RESET}")
    print(f" {izq}   {med}   {der}")


_ASCII = r"""
    ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
    ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
    ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
    ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
    ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
"""


def _banner():
    linea = "═" * 54
    out = [
        f"{C.VERDE2}╔{linea}╗{C.RESET}",
        f"{C.BOLD}{C.VERDE}{_ASCII.strip(chr(10))}{C.RESET}",
        f"{C.VERDE3}     ╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴{C.RESET}",
        f"     {C.DIM}{C.VERDE}v3.0{C.RESET}  {C.VERDE3}recon · scan · privesc · creds · monitor{C.RESET}",
        f"{C.VERDE2}╚{linea}╝{C.RESET}",
    ]
    return "\n".join(out)


BANNER = _banner()


# --------------------------------------------------------------------------- #
#  Utilidades de entrada/salida
# --------------------------------------------------------------------------- #
def _pedir(mensaje, por_defecto=None):
    try:
        valor = input(mensaje).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return por_defecto
    return valor or por_defecto


def _progreso(hechos, total, etiqueta="Progreso"):
    ancho = 30
    frac = hechos / total if total else 1
    lleno = int(ancho * frac)
    barra = "#" * lleno + "-" * (ancho - lleno)
    sys.stdout.write(f"\r{etiqueta}: [{barra}] {hechos}/{total}")
    sys.stdout.flush()
    if hechos >= total:
        sys.stdout.write("\n")


# --------------------------------------------------------------------------- #
#  Opcion 1: escaneo de red local
# --------------------------------------------------------------------------- #
def escanear_red_local():
    try:
        iface = red.obtener_interfaz()
    except RuntimeError as e:
        print(f"[!] {e}")
        return

    subred = red.calcular_red(iface["ip"], iface["netmask"])
    print(f"\nEquipo        : {iface['name']}")
    print(f"IP local      : {iface['ip']}")
    print(f"Mascara       : {iface['netmask']}")
    print(f"Broadcast     : {subred.broadcast_address}")
    print(f"Subred        : {subred}")

    ips = red.hosts_de_red(subred)
    print(f"\nHaciendo ping sweep a {len(ips)} direcciones...\n")

    total = len(ips)
    contador = {"n": 0}

    def cb(ip, vivo):
        contador["n"] += 1
        _progreso(contador["n"], total, "Ping sweep")

    vivos = escaner_local.ping_sweep(ips, callback=cb)

    if not vivos:
        print("\nNo se detectaron hosts activos.")
        return

    print(f"\nLeyendo tabla ARP para obtener direcciones MAC...")
    tabla_arp = escaner_local.leer_tabla_arp()

    print(f"\nHosts detectados ({len(vivos)}), identificando cada uno...\n")
    cabecera = (
        f"{'#':<4}{'IP':<16}{'MAC':<19}{'Hostname':<22}"
        f"{'Fabricante':<24}{'Tipo probable':<22}{'SO probable':<20}"
    )
    print(cabecera)
    print("-" * len(cabecera))

    hosts_ordenados = sorted(
        vivos.items(), key=lambda kv: socket.inet_aton(kv[0])
    )
    lista_ips = []
    for idx, (ip, ttl) in enumerate(hosts_ordenados, start=1):
        mac = tabla_arp.get(ip)
        info = identificador.identificar_host(ip, mac=mac, ttl=ttl)
        lista_ips.append(ip)
        SESION["hosts"].append(info)
        print(
            f"{idx:<4}{ip:<16}{info['mac']:<19}{info['hostname'][:21]:<22}"
            f"{info['vendor'][:23]:<24}{info['tipo_probable'][:21]:<22}"
            f"{info['so_probable']:<20}"
        )

    print()
    if _pedir("¿Escanear puertos de uno de estos hosts? (s/N): ", "n").lower() == "s":
        if len(lista_ips) == 1:
            objetivo = lista_ips[0]
        else:
            sel = _pedir(f"¿Cual host? (1-{len(lista_ips)}): ")
            try:
                objetivo = lista_ips[int(sel) - 1]
            except (ValueError, IndexError, TypeError):
                print("Seleccion no reconocida.")
                return
        escaneo_puertos(objetivo)


# --------------------------------------------------------------------------- #
#  Opcion 2: escaneo de host externo
# --------------------------------------------------------------------------- #
def escanear_host_externo():
    objetivo = _pedir("IP o dominio a escanear: ")
    if not objetivo:
        print("No se indico objetivo.")
        return
    try:
        ip = socket.gethostbyname(objetivo)
    except socket.gaierror:
        print(f"[!] No se pudo resolver '{objetivo}'.")
        return
    print(f"Objetivo resuelto: {objetivo} -> {ip}")
    escaneo_puertos(ip)


def escaneo_puertos(ip):
    print("\n¿Que puertos TCP escanear?")
    print("  1 - Puertos especificos (ej. 22,80,443 o 1-1024)")
    print("  2 - Los ~1000 puertos mas conocidos")
    print("  3 - Todos los 65535 (lento)")
    sel = _pedir("Escoge 1-3: ")

    if sel == "1":
        txt = _pedir("Puerto/s: ", "1-1024")
        try:
            puertos = escaner_externo.parsear_rango_puertos(txt)
        except ValueError:
            print("Formato de puertos invalido.")
            return
    elif sel == "2":
        puertos = escaner_externo.TOP_PUERTOS
    elif sel == "3":
        puertos = list(range(1, 65536))
    else:
        print("Seleccion no reconocida.")
        return

    if not puertos:
        print("No hay puertos que escanear.")
        return

    total = len(puertos)
    contador = {"n": 0}

    def cb(puerto, abierto):
        contador["n"] += 1
        _progreso(contador["n"], total, "Escaneo TCP")

    print(f"\nEscaneando {len(puertos)} puertos TCP en {ip}...\n")
    abiertos = escaner_externo.escanear_tcp(ip, puertos, callback=cb)

    if not abiertos:
        print("\nNo se encontraron puertos TCP abiertos.")
    else:
        print(f"\nPuertos TCP abiertos ({len(abiertos)}):\n")
        print(f"{'Puerto':<10}{'Servicio':<18}{'Banner':<48}")
        print("-" * 76)
        for p in abiertos:
            banner = (p["banner"] or "-")[:46]
            print(f"{p['puerto']:<10}{p['servicio']:<18}{banner:<48}")

    # Fingerprint extra del objetivo con los puertos hallados.
    puertos_abiertos = [p["puerto"] for p in abiertos]
    info = identificador.identificar_host(ip, puertos_abiertos=puertos_abiertos)
    print(f"\nHostname        : {info['hostname']}")
    print(f"Tipo probable   : {info['tipo_probable']}")

    if _pedir("\n¿Escanear tambien puertos UDP comunes? (s/N): ", "n").lower() == "s":
        print("\nSondeando puertos UDP comunes (best-effort)...\n")
        udp = escaner_externo.escanear_udp(ip)
        if not udp:
            print("Sin puertos UDP accesibles/abiertos detectados.")
        else:
            print(f"{'Puerto':<10}{'Servicio':<18}{'Estado':<20}")
            print("-" * 48)
            for p in udp:
                print(f"{p['puerto']:<10}{p['servicio']:<18}{p['estado']:<20}")

    # --- Fase de evaluacion: deteccion de version + vulnerabilidades ---
    if abiertos and _pedir(
        "\n¿Analizar servicios y vulnerabilidades (-sV + --vuln)? (s/N): ", "n"
    ).lower() == "s":
        analisis_vulnerabilidades(ip, puertos_abiertos)


def analisis_vulnerabilidades(ip, puertos_abiertos):
    """Deteccion de version (-sV) + motor CVE y scripts seguros (--vuln/-sC)."""
    print(f"\nDetectando servicios y versiones en {len(puertos_abiertos)} puertos...")
    detectados = servicios.detectar_varios(ip, puertos_abiertos)

    for s in detectados:
        s["ip"] = ip
        SESION["servicios"].append(s)
    _titulo("deteccion de servicios")
    _tabla(["PUERTO", "SERVICIO", "PRODUCTO", "VERSION", "INFO"],
           [6, 9, 18, 11, 38],
           [[s["puerto"], s["servicio"], s["producto"], s["version"], s["extra"]]
            for s in detectados])

    print(f"\n{C.DIM}Analizando vulnerabilidades (motor CVE + scripts seguros)...{C.RESET}")
    hallazgos = vulnerabilidades.analizar(ip, detectados)

    # Auditoria web (estilo Nikto) en cada puerto web detectado.
    web = [s for s in detectados if s["servicio"] in ("http", "https")]
    if web:
        print(f"{C.DIM}web: rutas, cabeceras, cookies, cors, metodos...{C.RESET}")
        for s in web:
            try:
                hallazgos += escaner_web.auditar_web(
                    ip, s["puerto"], usar_tls=s["servicio"] == "https")
            except Exception:
                pass
        hallazgos.sort(key=lambda h: {"Critica": 0, "Alta": 1, "Media": 2,
                                      "Baja": 3, "Info": 4}.get(h["sev"], 9))

    for h in hallazgos:
        h["ip"] = ip
    SESION["vulnerabilidades"].extend(hallazgos)

    if not hallazgos:
        print(_c("\nSin hallazgos. (Ausencia de hallazgos != sistema seguro.)", C.VERDE))
        return

    criticas = sum(1 for h in hallazgos if h["sev"] in ("Critica", "Alta"))
    resumen = f"{len(hallazgos)} hallazgos · {criticas} de severidad alta/critica"
    _titulo(resumen)
    _tabla(["SEV", "PUERTO", "CVE / REF", "HALLAZGO"], [8, 6, 24, 44],
           [[h["sev"], h.get("puerto", "-"), str(h.get("cve", "-")), h["titulo"]]
            for h in hallazgos], color_fila=_color_sev_fila)

    if _pedir("\n¿Ver detalle y remediaciones? (s/N): ", "n").lower() == "s":
        for i, h in enumerate(hallazgos, 1):
            print(f"\n[{i}] ({h['sev']}) puerto {h.get('puerto','-')} - {h['titulo']}")
            if h.get("cve", "-") not in ("-", "N/A"):
                print(f"    CVE/Ref   : {h['cve']}  (CVSS {h.get('cvss', 0)})")
            if h.get("evidencia"):
                print(f"    Evidencia : {h['evidencia']}")
            if h.get("remediacion"):
                print(f"    Remediar  : {h['remediacion']}")


# --------------------------------------------------------------------------- #
#  Opcion 3: auditoria local de escalada de privilegios
# --------------------------------------------------------------------------- #
def auditoria_privesc():
    _titulo("escalada de privilegios local")
    hallazgos = privesc.auditar_local()
    SESION["privesc"] = hallazgos

    _tabla(["SEV", "CATEGORIA", "DETALLE"], [8, 32, 44],
           [[h["sev"], h["categoria"], h["detalle"]] for h in hallazgos],
           color_fila=_color_sev_fila)

    if _pedir("\n¿Ver recomendaciones y tecnicas? (s/N): ", "n").lower() == "s":
        for i, h in enumerate(hallazgos, 1):
            print(f"\n[{i}] ({h['sev']}) {h['categoria']}")
            print(f"    Detalle  : {h['detalle']}")
            if h.get("recomendacion"):
                print(f"    Accion   : {h['recomendacion']}")
            if h.get("tecnica"):
                print(f"    Tecnica  : {h['tecnica']}")
            if h.get("referencia"):
                print(f"    Referencia: {h['referencia']}")


# --------------------------------------------------------------------------- #
#  Opcion 4: auditor de contrasenas
# --------------------------------------------------------------------------- #
def auditoria_passwords():
    _titulo("fuerza de contrasenas")
    while True:
        pwd = _pedir("\npassword (enter para terminar): ", "")
        if not pwd:
            break
        r = password_audit.evaluar_password(pwd)
        color = _COLOR_SEV.get(
            {"Muy debil": "Critica", "Debil": "Alta", "Aceptable": "Media",
             "Fuerte": "Baja", "Muy fuerte": "Info"}.get(r["nivel"], "Info"), "")
        print(f"  Nivel: {color}{r['nivel']}{C.RESET}  "
              f"({r['bits']} bits, {r['longitud']} caracteres)")
        for c in r["consejos"]:
            print(f"   - {c}")

    _titulo("politica de cuentas")
    for linea in password_audit.auditar_politica_local():
        print(f"  {linea}")


# --------------------------------------------------------------------------- #
#  Opcion 5: auditoria de hashes (diccionario / fuerza bruta)
# --------------------------------------------------------------------------- #
def auditoria_hashes():
    _titulo("auditoria de hashes")
    print(f"{C.DIM}{cracker.nota_entorno()}{C.RESET}")
    print(f"{C.DIM}pega un hash, o ruta de archivo (hash | user:hash | shadow).{C.RESET}")
    entrada = _pedir("\nhash o archivo: ", "")
    if not entrada:
        print(f"{C.ROJO}[!] sin entrada{C.RESET}")
        return

    texto = entrada
    if os.path.isfile(entrada):
        try:
            with open(entrada, "r", encoding="latin-1", errors="ignore") as f:
                texto = f.read()
        except OSError as e:
            print(f"{C.ROJO}[!] no se pudo leer: {e}{C.RESET}")
            return

    entradas = cracker.cargar_hashes(texto)
    if not entradas:
        print(f"{C.ROJO}[!] no se reconocio ningun hash{C.RESET}")
        return

    _tabla(["USUARIO", "TIPO(S)", "HASH"], [16, 16, 40],
           [[e["usuario"] or "-", ",".join(e["tipos"]), e["hash"]] for e in entradas])

    wl = _pedir(f"\nwordlist (enter = lista embebida ~{len(password_audit.COMUNES)}): ", "")
    print(f"{C.DIM}crackeando por diccionario...{C.RESET}")

    def cb(intentos, hallados):
        sys.stdout.write(f"\r{C.VERDE2}  intentos: {intentos}  hallados: {hallados}{C.RESET}")
        sys.stdout.flush()

    encontrados = cracker.crackear_diccionario(entradas, wl or None, callback=cb)
    print()

    faltan = [e for e in entradas if e["hash"] not in encontrados
              and e["tipos"][0] in cracker._FUNCS]
    if faltan and _pedir(
        "\n¿Fuerza bruta corta (<=4, lento) sobre lo no crackeado? (s/N): ", "n"
    ).lower() == "s":
        print(f"{C.DIM}fuerza bruta (puede tardar)...{C.RESET}")
        encontrados.update(cracker.crackear_fuerza_bruta(faltan, max_len=4, callback=cb))
        print()

    filas, sesion = [], []
    for e in entradas:
        pwd = encontrados.get(e["hash"])
        estado = "CRACKEADO" if pwd else "pendiente"
        filas.append([e["usuario"] or "-", e["tipos"][0], estado, pwd or "-"])
        sesion.append({"usuario": e["usuario"] or "-", "tipo": e["tipos"][0],
                       "estado": estado, "password": pwd or "-"})
    SESION["hashes"] = sesion

    _titulo(f"resultados · {len(encontrados)}/{len(entradas)} crackeados")
    _tabla(["USUARIO", "TIPO", "ESTADO", "PASSWORD"], [16, 10, 11, 28], filas,
           color_fila=lambda f, i: C.VERDE if f[2] == "CRACKEADO" else C.ROJO)


# --------------------------------------------------------------------------- #
#  Opcion 5: monitor local (conexiones + WiFi)
# --------------------------------------------------------------------------- #
def monitor_local():
    _titulo("conexiones")
    conexiones = recon_local.conexiones_activas()
    SESION["conexiones"] = conexiones
    expuestas = recon_local.conexiones_destacadas(conexiones)
    ids_exp = {id(cx) for cx in expuestas}
    print(f"{C.DIM}{len(conexiones)} entradas · {C.AMAR}{len(expuestas)} escuchas "
          f"expuestas (0.0.0.0/::){C.RESET}\n")
    cxs = conexiones[:40]
    filas = [[cx["proto"], cx["local"], cx["remoto"], cx["estado"], str(cx["pid"])]
             for cx in cxs]
    _tabla(["PROTO", "LOCAL", "REMOTO", "ESTADO", "PID"], [6, 24, 24, 12, 7], filas,
           color_fila=lambda f, i: C.AMAR if id(cxs[i]) in ids_exp else C.BLANCO)
    if len(conexiones) > 40:
        print(f"{C.DIM}... y {len(conexiones) - 40} mas (en el reporte completo).{C.RESET}")

    _titulo("wifi")
    redes = recon_local.redes_wifi()
    SESION["wifi"] = redes
    if not redes:
        print(f"{C.DIM}No se detectaron redes (¿adaptador WiFi presente/activo?).{C.RESET}")
    else:
        inseguras = recon_local.wifi_inseguras(redes)
        ids_ins = {id(w) for w in inseguras}
        filas = [[w["ssid"], w["auth"], w["cifrado"]] for w in redes]
        _tabla(["SSID", "AUTENTICACION", "CIFRADO"], [28, 20, 13], filas,
               color_fila=lambda f, i: C.ROJO if id(redes[i]) in ids_ins else C.VERDE)
        if inseguras:
            print(_c(f"\n[!] {len(inseguras)} red(es) con cifrado debil (abierta/WEP).", C.ROJO))


# --------------------------------------------------------------------------- #
#  Opcion 6: generar reporte
# --------------------------------------------------------------------------- #
def generar_reporte():
    _titulo("reporte")
    vacia = not any(SESION[k] for k in ("hosts", "servicios", "vulnerabilidades",
                                        "privesc", "conexiones", "wifi", "hashes"))
    if vacia:
        print(f"{C.DIM}Aun no hay resultados. Corre primero un escaneo o auditoria.{C.RESET}")
        return
    carpeta = os.path.dirname(os.path.abspath(__file__))
    try:
        ruta_json, ruta_html = reporte.generar(SESION, carpeta)
    except OSError as e:
        print(f"[!] No se pudo escribir el reporte: {e}")
        return
    print(f"  {C.VERDE}JSON:{C.RESET} {ruta_json}")
    print(f"  {C.VERDE}HTML:{C.RESET} {ruta_html}")
    print(f"{C.DIM}Abre el HTML en tu navegador para ver el informe completo.{C.RESET}")


# --------------------------------------------------------------------------- #
#  Menu principal
# --------------------------------------------------------------------------- #
_OPCIONES = [
    ("1", "netscan ", "Escanear red local (descubrir hosts)"),
    ("2", "portscan", "Host externo (puertos · -sV · vuln · web)"),
    ("3", "privesc ", "Auditoria local de escalada de privilegios"),
    ("4", "passwd  ", "Auditor de robustez de contrasenas"),
    ("5", "hashes  ", "Auditar hashes (diccionario / fuerza bruta)"),
    ("6", "netstat ", "Conexiones activas + redes WiFi"),
    ("7", "report  ", "Generar reporte HTML / JSON"),
    ("8", "exit    ", "Salir"),
]


def _menu_caja():
    b = C.VERDE2
    ancho = 60
    print(_c("┌" + "─" * ancho + "┐", b))
    titulo = "modules"
    print(_c("│", b) + f" {C.VERDE2}{titulo}{C.RESET}"
          + " " * (ancho - 1 - len(titulo)) + _c("│", b))
    print(_c("├" + "─" * ancho + "┤", b))
    for num, tag, desc in _OPCIONES:
        linea = f" {C.VERDE}[{num}]{C.RESET} {C.CIAN}{tag}{C.RESET} {C.VERDE3}»{C.RESET} {C.BLANCO}{desc}{C.RESET}"
        visible = len(f" [{num}] {tag} » {desc}")
        print(_c("│", b) + linea + " " * max(0, ancho - visible) + _c("│", b))
    print(_c("└" + "─" * ancho + "┘", b))


def menu():
    print(BANNER)
    _barra_estado()
    while True:
        print()
        _menu_caja()
        sel = _pedir(f"\n{C.VERDE2}┌──({C.ROJO}root{C.VERDE2}㉿{C.VERDE}wraith{C.VERDE2})\n└─{C.VERDE}#{C.RESET} ")

        if sel is None:  # EOF / Ctrl+D: salir sin bucle infinito
            print(f"\n{C.VERDE2}[*] eof{C.RESET}")
            break
        if sel == "1":
            escanear_red_local()
        elif sel == "2":
            escanear_host_externo()
        elif sel == "3":
            auditoria_privesc()
        elif sel == "4":
            auditoria_passwords()
        elif sel == "5":
            auditoria_hashes()
        elif sel == "6":
            monitor_local()
        elif sel == "7":
            generar_reporte()
        elif sel == "8":
            print(f"{C.VERDE2}[*] saliendo{C.RESET}")
            break
        else:
            print(f"{C.ROJO}[!] opcion invalida{C.RESET}")


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(f"\n{C.ROJO}[!] interrumpido{C.RESET}")