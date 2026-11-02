import nmap
import socket

escaneo = nmap.PortScanner()
ip = input("Ingresa el IP a escanear: ")
hosts = socket.gethostbyname(ip)
ports = input("Ingresa el puerto a escanear: ")

def escaneo_normal(escaneo,hosts,ports):
    arguments = input("Ingresa las flags: ")
    escaneo.scan(hosts,ports,arguments)
    for host in escaneo.all_hosts():
        print(f"Host: {host} - Estado: {escaneo[host].state()}")
        for proto in escaneo[host].all_protocols():
            for puerto in escaneo[host][proto]:
                info = escaneo[host][proto][puerto]
                print(f"  Puerto {puerto}/{proto}: {info['state']} - {info.get('name','')} {info.get('version','')}")

print("1 - Escaneo")
print("2 - Salir")

opcion = input("Escoje una opcion: ")
if opcion == "1":
    escaneo_normal(escaneo,hosts,ports)
elif opcion == "2":
    print("Hasta luego")
    None
else:
    print("Error")
