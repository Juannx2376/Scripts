"""Logica de TTL, Hostname y Huella (Fingerprinting).

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
