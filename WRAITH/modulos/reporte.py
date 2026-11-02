"""Generador de reportes (estilo Nessus/OpenVAS).

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
