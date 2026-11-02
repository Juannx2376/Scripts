import random
import string
import base64
import os
import json
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

print("Password Manager")

CARPETA = Path.home() / ".password_manager"
CARPETA.mkdir(exist_ok=True)

ARCHIVO_SALT = CARPETA / "salt.bin"

ARCHIVO_BOVEDA = CARPETA / "boveda.json"


if ARCHIVO_SALT.exists() == True:
    salt = ARCHIVO_SALT.read_bytes()
elif ARCHIVO_SALT.exists() == False:
    salt = os.urandom(16)
    ARCHIVO_SALT.write_bytes(salt)
else:
    None

def derivar_llave(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def cifrado_y_guardado(master_password):
    servicio = input("¿Para qué servicio? (ej. gmail): ")
    contrasenia = input("Contraseña a guardar: ")
    guardar_en_boveda(servicio, contrasenia, master_password)

def contrasenia_aleatoria():
    caracteres = string.ascii_letters + string.digits + string.punctuation
    longitud = 16
    password = "".join(random.choices(caracteres, k=longitud))
    print(f"Contrasela generada: {password}")
    return password

def guardar_en_boveda(servicio, contrasenia, master_password):
    llave = derivar_llave(master_password, salt)
    f = Fernet(llave)
    cifrada = f.encrypt(contrasenia.encode())

    if ARCHIVO_BOVEDA.exists():
        datos = json.loads(ARCHIVO_BOVEDA.read_text())
    else:
        datos = {}

    datos[servicio] = cifrada.decode()
    ARCHIVO_BOVEDA.write_text(json.dumps(datos, indent=2))
    print(f"✅ Contraseña de '{servicio}' guardada.")

def ver_contrasenia(master_password):
    llave = derivar_llave(master_password, salt)
    f = Fernet(llave)
    datos = json.loads(ARCHIVO_BOVEDA.read_text())
    servicio = input("¿Qué servicio quieres ver?: ")

    try:
        cifrada = datos[servicio]
        descifrada = f.decrypt(cifrada.encode()).decode()
        print(f"🔑 Contraseña de '{servicio}': {descifrada}")
    except KeyError:
        print("Servicio desconocido")
    except InvalidToken:
        print("Master password incorrecta")

def listar_servicios():
    if not ARCHIVO_BOVEDA.exists():
        print("No hay contraseñas guardadas todavía.")
        return

    datos = json.loads(ARCHIVO_BOVEDA.read_text())
    if not datos:
        print("La bóveda está vacía.")
        return

    print("\n📋 Servicios guardados:")
    for servicio in datos:
        print(f"  - {servicio}")

while True:
    print("1 - Guardar una contraseña")
    print("2 - Generar una contraseña")
    print("3 - Ver una contraseña")
    print("4 - Salir")

    opcion = input("Selecciona opcion: ")
    if opcion == "1":
        master_password =  input("Ingresa tu master password: ")
        cifrado_y_guardado(master_password)
    elif opcion == "2":
        generada = contrasenia_aleatoria()
        guardar = input("¿Quieres guardarla en la bóveda? (s/n): ")
        if guardar.lower() == "s":
            master_password = input("Ingresa tu master password: ")
            servicio = input("¿Para qué servicio?: ")
            guardar_en_boveda(servicio, generada, master_password)
    elif opcion == "3":
        if ARCHIVO_BOVEDA.exists():
            master_password =  input("Ingresa tu master password: ")
            listar_servicios()
            ver_contrasenia(master_password)
        else:
            print("No hay contraseñas guardadas todavía.")
    elif opcion == "4":
        print("¡Regresa pronto!")
        break
    else:
        print("Error")
