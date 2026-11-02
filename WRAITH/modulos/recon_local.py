"""Monitor local de red (alternativa defensiva a Wireshark/Aircrack).

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
