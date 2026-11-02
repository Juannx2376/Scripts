import nmap
import socket
import struct
from scapy.all import conf, Ether, ARP, IP, ICMP, sr1, srp
import ipaddress

scanner = nmap.PortScanner()

def _obtener_interfaz(destino="1.1.1.1"):
    iface, ip, gateway = conf.route.route(destino)
    if not ip or ip == "0.0.0.0":
        raise RuntimeError("No se encontró una interfaz con salida a la red.")

    netmask = "255.255.255.0"
    for red_destino, mask, gw, ruta_iface, addr, metric in conf.route.routes:
        if ruta_iface == iface and addr == ip and red_destino != 0:
            netmask = socket.inet_ntoa(struct.pack("!I", mask))
            break

    return {'name': iface, 'ip': ip, 'netmask': netmask}

def _calcular_red(ip, netmask):
    return ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)

_REGLAS_TIPO = [
    (("raspberry",), "Raspberry Pi"),
    (("apple",), "Apple (iPhone/iPad/Mac)"),
    (("samsung",), "Samsung (movil/TV)"),
    (("xiaomi",), "Xiaomi (movil/IoT)"),
    (("huawei",), "Huawei (movil/router)"),
    (("espressif",), "IoT (ESP32/ESP8266)"),
    (("tp-link", "d-link", "netgear", "mikrotik", "ubiquiti", "cisco", "huawei technologies"), "Router / Access Point"),
    (("vmware", "virtualbox", "microsoft hyper-v", "parallels", "innotek"), "Maquina virtual"),
    (("intel", "dell", "hewlett", "hp inc", "lenovo", "asustek", "gigabyte", "msi"), "PC / Laptop"),
    (("amazon", "roku", "google"), "Streaming / Smart home"),
    (("sonos", "espressif", "shenzhen", "tuya"), "IoT / domotica"),
]

def _adivinar_tipo(vendor):
    vendor_lower = vendor.lower()
    for claves, etiqueta in _REGLAS_TIPO:
        if any(clave in vendor_lower for clave in claves):
            return etiqueta
    return "Desconocido"

def _ttl_a_so(ttl):
    if ttl is None:
        return "Desconocido"
    if ttl <= 64:
        return "Linux/Android/macOS"
    if ttl <= 128:
        return "Windows"
    return "Otro/Router"

def _identificar_host(ip, mac):
    try:
        vendor = conf.manufdb._get_manuf(mac) or "Desconocido"
    except Exception:
        vendor = "Desconocido"

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = "-"

    ttl = None
    try:
        respuesta = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=0)
        if respuesta is not None:
            ttl = respuesta.ttl
    except Exception:
        pass

    return {
        'hostname': hostname,
        'vendor': vendor,
        'tipo_probable': _adivinar_tipo(vendor),
        'so_probable': _ttl_a_so(ttl),
    }


def escanear_red():
    iface = _obtener_interfaz()
    red = _calcular_red(iface['ip'], iface['netmask'])
    print(f"Interfaz elegida: {iface['name']}")
    print(f"IP: {iface['ip']}\tNetmask: {iface['netmask']}\tBroadcast: {red.broadcast_address}")
    print(f"\nEscaneando la red: {red}")

    conf.iface = iface['name']

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(red))
    answered, _ = srp(arp_request, timeout=2, retry=1, verbose=0)

    hosts_detectados = [recv.psrc for _, recv in answered]
    if not hosts_detectados:
        print("\nNo se detectaron hosts.")
        return

    print(f"\nHosts detectados ({len(hosts_detectados)}), identificando cada uno...")
    print(f"\n{'#':<4}{'IP':<16}{'MAC':<19}{'Hostname':<25}{'Fabricante':<25}{'Tipo probable':<25}{'SO probable':<20}")
    print("-" * 130)
    for idx, (_, recv) in enumerate(answered, start=1):
        info = _identificar_host(recv.psrc, recv.hwsrc)
        print(
            f"{idx:<4}{recv.psrc:<16}{recv.hwsrc:<19}{info['hostname']:<25}"
            f"{info['vendor']:<25}{info['tipo_probable']:<25}{info['so_probable']:<20}"
        )

    print("\n¿Quieres seguir con una busqueda de Vulnerabilidades y Servicios?:")
    print("1 - Si")
    print("2 - No")

    seleccion_vulnerabilidades = input("Ingresa seleccion: ")

    if seleccion_vulnerabilidades == "1":
        if len(hosts_detectados) == 1:
            ip_objetivo = hosts_detectados[0]
        else:
            seleccion_host = input(f"¿Cual host escaneas? (1-{len(hosts_detectados)}): ")
            try:
                ip_objetivo = hosts_detectados[int(seleccion_host) - 1]
            except (ValueError, IndexError):
                print("Seleccion no reconocida")
                return
        vulnerabilidades(ip_objetivo)
    elif seleccion_vulnerabilidades == "2":
        print("!Regresa pronto¡")
    else:
        print("Seleccion no reconocida")

def analisis(scanner):
    objetivo = input("IP o dominio a escanear: ")
    ip = socket.gethostbyname(objetivo)
    print("¿Analizar puertos especificos, los mil puertos mas conocidos o todos los 65535? (1-2-3)")
    seleccion_puerto = input("Escoje 1-2-3: ")
    if  seleccion_puerto == "1":
        puerto = input("Puerto/s a escanear: ")
    elif seleccion_puerto == "2":
        puerto = None
    elif seleccion_puerto == "3":
        puerto = "1-65535"
    else:
        print("Seleccion no reconocida")
        return

    print(f"Escaneando {ip}...")
    scanner.scan(ip, puerto)

    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"Estado: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"Protocolo: {proto}")
            puertos = sorted(scanner[host][proto].keys())
            for puerto in puertos:
                estado = scanner[host][proto][puerto]["state"]
                print(f"  Puerto: {puerto}\tEstado: {estado}")

    print("¿Quieres seguir con una busqueda de Vulnerabilidades y Servicios?:")

    print("1 - Si")
    print("2 - No")

    seleccion_vulnerabilidades = input("Ingresa seleccion: ")

    if seleccion_vulnerabilidades == "1":
        vulnerabilidades(ip)
    elif seleccion_vulnerabilidades == "2":
        print("!Regresa pronto¡")
    else:
        print("Seleccion no reconocida")

def vulnerabilidades(ip):
    puerto = input("Puerto/s a escanear (enter para 1-1024): ") or "1-1024"

    print(f"Buscando vulnerabilidades y servicios en {ip}, esto puede tardar unos minutos...")
    scanner.scan(ip, puerto, arguments="-sV --script vuln")

    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"Estado: {scanner[host].state()}")

        print(f"\n{'Puerto':<10}{'Servicio':<20}{'Vulnerabilidad':<50}")
        print("-" * 80)
        for proto in scanner[host].all_protocols():
            for num_puerto in sorted(scanner[host][proto].keys()):
                datos = scanner[host][proto][num_puerto]
                servicio = datos.get("name", "-")
                scripts = datos.get("script", {})
                if not scripts:
                    print(f"{num_puerto:<10}{servicio:<20}{'Sin hallazgos':<50}")
                    continue
                for script_id, salida in scripts.items():
                    resumen = next((l.strip() for l in salida.splitlines() if l.strip()), "Sin salida")
                    print(f"{num_puerto:<10}{servicio:<20}{script_id + ': ' + resumen:<50}")

        for script in scanner[host].get("hostscript", []):
            resumen = next((l.strip() for l in script["output"].splitlines() if l.strip()), "Sin salida")
            print(f"{'-':<10}{'host':<20}{script['id'] + ': ' + resumen:<50}")

BANNER = r"""
 _  _     _                  _     ___
| \| |___| |___ __ _____ _ _| |__ / __| __ __ _ _ _  _ _  ___ _ _
| .` / -_)  _\ V  V / _ \ '_| / / \__ \/ _/ _` | ' \| ' \/ -_) '_|
|_|\_\___|\__|\_/\_/\___/_| |_\_\ |___/\__\__,_|_||_|_||_\___|_|
"""

if __name__ == "__main__":
    print(BANNER)

    print("1 - Escanear red local")
    print("2 - Escanear red externa")
    print("3 - Salir")

    seleccion = input("Ingresa una seleccion: ")


    if seleccion == "1":
        escanear_red()
    elif seleccion == "2":
        analisis(scanner)
    elif seleccion == "3":
        print("¡Regresa pronto!")
    else:
        print("Seleccion no reconocida")
            
