import re
from collections import Counter

def extraer_ip_fallido(linea):
    if "Failed password" in linea:
        match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", linea)
        if match:
            return match.group()
    return None

def analizar_log(ruta):
    contador = Counter()
    try:
        with open(ruta, "r", encoding="latin-1", errors="ignore") as f:
            for linea in f:
                ip = extraer_ip_fallido(linea)
                if ip:
                    contador[ip] += 1
    except FileNotFoundError:
        print("Archivo no encontrado")
        return None
    return contador

def detectar_ataques(contador, umbral=10):
    sospechosos = []
    for ip, intentos in contador.items():
        if intentos >= umbral:
            sospechosos.append((ip, intentos))
    sospechosos.sort(key=lambda x: x[1], reverse=True)
    return sospechosos

def generar_reporte(ruta, umbral=10):
    contador = analizar_log(ruta)
    if contador is None:
        return

    total_fallos = sum(contador.values())
    sospechosos = detectar_ataques(contador, umbral)

    print("Reporte de Analisis de Log")

    print(f"Total de intentos fallidos: {total_fallos}")
    print(f"IPs unicas con fallos     : {len(contador)}")
    print(f"Umbral de alerta          : {umbral} intentos\n")

    if sospechosos:
        print(f"{len(sospechosos)} IP(s) Sospechosa(s) de ataque: ")
        for ip, intentos in sospechosos:
            print(f"    [Alerta] {ip} -> {intentos} intentos fallidos")
    else:
        print("No se detectaron ataques (ninguna IP supero el umbral)")

if __name__ == "__main__":
    print("Analizador de Logs")
    ruta = input("Ruta del archivo de log: ").strip()
    umbral = input("Umbral de alerta (enter = 10): ").strip()
    umbral = int(umbral) if umbral else 10
    generar_reporte(ruta, umbral)