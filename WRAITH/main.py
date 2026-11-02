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

from modulos import red, escaner_local, escaner_externo, identificador, servicios, vulnerabilidades, privesc, sistema, escaner_web, password_audit, recon_local, reporte, cracker

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
