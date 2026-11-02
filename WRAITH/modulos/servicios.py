"""Deteccion de servicios y versiones (equivalente nativo a `nmap -sV`).

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
