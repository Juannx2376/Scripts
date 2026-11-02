#!/usr/bin/env python3
"""Script auxiliar: une todos los modulos en un solo archivo .py portable.

Genera `wraith.py`, que no necesita la carpeta `modulos/` y se puede copiar a
cualquier maquina con Python 3 instalado.

Tecnica: embebe el codigo fuente de cada modulo como texto y lo registra en
sys.modules en tiempo de ejecucion, de modo que los `import` del main siguen
funcionando sin cambios.

Uso:
    python exportador.py
"""

import os

AQUI = os.path.dirname(os.path.abspath(__file__))
MODULOS = ["sistema", "red", "escaner_local", "escaner_externo",
           "identificador", "servicios", "vulnerabilidades", "privesc",
           "escaner_web", "password_audit", "cracker", "recon_local", "reporte"]
SALIDA = os.path.join(AQUI, "wraith.py")

CABECERA = '''#!/usr/bin/env python3
"""WRAITH - version unificada autocontenida.

Generado automaticamente por exportador.py a partir de los modulos del
proyecto. No requiere la carpeta modulos/. Multiplataforma (Windows/Linux).
"""

import sys
import types


def _registrar_modulo(nombre, codigo):
    """Crea un modulo en memoria desde codigo fuente y lo registra."""
    mod = types.ModuleType(nombre)
    mod.__dict__["__name__"] = nombre
    exec(compile(codigo, f"<{nombre}>", "exec"), mod.__dict__)
    sys.modules[nombre] = mod
    # Alias con prefijo de paquete para que "from modulos import X" funcione.
    sys.modules["modulos." + nombre] = mod
    return mod


# Paquete virtual "modulos" para que los imports del main resuelvan.
_paquete = types.ModuleType("modulos")
_paquete.__path__ = []  # marca como paquete
sys.modules["modulos"] = _paquete

'''


def _leer(ruta):
    with open(ruta, "r", encoding="utf-8") as f:
        return f.read()


def construir():
    partes = [CABECERA]

    # 1) Embeber cada modulo como string y registrarlo (respetando el orden).
    for nombre in MODULOS:
        ruta = os.path.join(AQUI, "modulos", f"{nombre}.py")
        codigo = _leer(ruta)
        partes.append(f"# --- modulo: {nombre} ---\n")
        partes.append(f"_CODIGO_{nombre.upper()} = r'''{_escapar(codigo)}'''\n")
        partes.append(
            f'_registrar_modulo("{nombre}", _CODIGO_{nombre.upper()})\n'
            f'setattr(_paquete, "{nombre}", sys.modules["{nombre}"])\n\n'
        )

    # 2) Anexar el cuerpo del main (sin su bloque de imports de modulos).
    main_codigo = _leer(os.path.join(AQUI, "main.py"))
    main_codigo = _quitar_import_modulos(main_codigo)
    partes.append("# --- cuerpo principal (main.py) ---\n")
    partes.append(main_codigo)

    with open(SALIDA, "w", encoding="utf-8") as f:
        f.write("".join(partes))

    print(f"[OK] Generado: {SALIDA}")
    print(f"     Ejecutalo con:  python {os.path.basename(SALIDA)}")


def _escapar(codigo):
    """Evita que un triple-quote dentro del codigo rompa el string literal."""
    return codigo.replace("'''", "\\'\\'\\'")


def _quitar_import_modulos(main_codigo):
    """Quita la linea 'from modulos import ...'; los modulos ya estan en memoria."""
    lineas = []
    for linea in main_codigo.splitlines():
        if linea.strip().startswith("from modulos import"):
            lineas.append("# (imports de modulos resueltos en memoria)")
            # Reconstruimos los nombres como alias directos al namespace.
            nombres = linea.split("import", 1)[1]
            # Limpia parentesis/espacios por si el import fuese multilinea.
            nombres = nombres.replace("(", "").replace(")", "")
            for n in [x.strip() for x in nombres.split(",")]:
                if n and n.isidentifier():
                    lineas.append(f"{n} = sys.modules['{n}']")
            continue
        lineas.append(linea)
    return "\n".join(lineas)


if __name__ == "__main__":
    construir()
