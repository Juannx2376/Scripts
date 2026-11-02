import socket
import dns.resolver
import requests
import whois

def registros_dns(dominio):
    tipos = ["MX", "TXT", "NS", "AAAA", "A"]
    for tipo in tipos:
        try:
            respuestas = dns.resolver.resolve(dominio, tipo)
            print(f"\n[{tipo}]")
            for r in respuestas:
                print(f"    {r.to_text()}")
        except Exception as e:
            print(f"\n[{tipo}] sin registros ({type(e).__name__})")

def resolver_ip(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        print(f"{dominio} -> {ip}")
        return ip
    except socket.gaierror:
        print(f"No se pudo resolver {dominio}")
        return None

def buscar_subdominios(dominio):
    comunes = ["www", "mail", "ftp", "admin", "panel", "webmail", "smtp", "ns1", "cpanel", "ns2", "test", "dev", "api", "blog", "vpn", "portal", "m", "shop", "secure"]

    print(f"\nBuscando subdominios de {dominio}...")
    encontrados = []
    for sub in comunes:
        subdominio = f"{sub}.{dominio}"
        try:
            ip = socket.gethostbyname(subdominio)
            print(f"    {subdominio} -> {ip}")
            encontrados.append(subdominio)
        except socket.gaierror:
            pass
    return encontrados

def cabeceras_http(dominio):
    print(f"\nCabeceras HTTP de {dominio}...")
    try:
        respuesta = requests.get(f"http://{dominio}", timeout=5)
        print(f"    Estado: {respuesta.status_code}")
        for clave, valor in respuesta.headers.items():
            print(f"    {clave}: {valor}")
    except requests.RequestException as e:
        print(f"    Error: {type(e).__name__}")

def info_whois(dominio):
    print(f"\nWHOIS de {dominio}...")
    try:
        datos = whois.whois(dominio)
        print(f"    Registrador : {datos.registrar}")
        print(f"    Creado      : {datos.creation_date}")
        print(f"    Expira      : {datos.expiration_date}")
        print(f"    Pais        : {datos.country}")
        print(f"    Servidores  : {datos.name_servers}")
    except Exception as e:
        print(f"    Error: {type(e).__name__}")

if __name__ == "__main__":
    while True:
        print("OSINT Tool")
        print("1 - Resolver IP")
        print("2 - Registro DNS")
        print("3 - Buscar subdominios")
        print("4 - Cabeceras HTTP")
        print("5 - WHOIS")
        print("6 - Analisis completo")
        print("7 - Salir")

        opcion = input("Selecciona una opcion: ")

        if opcion in ("1", "2", "3", "4", "5", "6"):
            dominio = input("Ingresa dominio a investigar: ").strip()

        if opcion == "1":
            resolver_ip(dominio)
        elif opcion == "2":
            registros_dns(dominio)
        elif opcion == "3":
            buscar_subdominios(dominio)
        elif opcion == "4":
            cabeceras_http(dominio)
        elif opcion == "5":
            info_whois(dominio)
        elif opcion == "6":
            resolver_ip(dominio)
            registros_dns(dominio)
            buscar_subdominios(dominio)
            cabeceras_http(dominio)
            info_whois(dominio)
        elif opcion == "7":
            print("Saliendo...")
            break
        else:
            print("Instruccion desconocida")