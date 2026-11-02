import subprocess

resultado = subprocess.run(
    ["find", "/", "-perm", "-4000", "-type", "f"],
    stdout=subprocess.PIPE,      # captura la salida (los binarios SUID)
    stderr=subprocess.DEVNULL,   # descarta los errores (permiso denegado)
    text=True
)

print(resultado.stdout)

