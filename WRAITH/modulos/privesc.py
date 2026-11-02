"""Auditor local de escalada de privilegios (estilo WinPEAS / LinPEAS).

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
