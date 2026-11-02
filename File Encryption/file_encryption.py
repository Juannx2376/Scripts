import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass

def cifrar_archivo(ruta, password):
    salt = os.urandom(16)                   
    llave = derivar_llave(password, salt)
    f = Fernet(llave)

    datos = Path(ruta).read_bytes()          
    cifrado = f.encrypt(datos)               

    Path(ruta + ".enc").write_bytes(salt + cifrado)  
    print(f"Archivo cifrado: {ruta}.enc")

def descifrar_archivo(ruta, password):
    contenido = Path(ruta).read_bytes()      

    salt = contenido[:16]                    
    cifrado = contenido[16:]                 

    llave = derivar_llave(password, salt)   
    f = Fernet(llave)

    datos = f.decrypt(cifrado)               

    ruta_salida = ruta.replace(".enc", "")   
    Path(ruta_salida).write_bytes(datos)     
    print(f"Archivo descifrado: {ruta_salida}")


def derivar_llave(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

if __name__ == "__main__":
    while True:
        print("\n=== File Encryptor ===")
        print("1 - Cifrar un archivo")
        print("2 - Descifrar un archivo")
        print("3 - Salir")

        opcion = input("Selecciona opción: ")

        if opcion == "1":
            ruta = input("Ruta del archivo a cifrar: ")
            password = getpass("Contraseña: ")
            cifrar_archivo(ruta, password)
        elif opcion == "2":
            ruta = input("Ruta del archivo .enc a descifrar: ")
            password = getpass("Contraseña: ")
            descifrar_archivo(ruta, password)
        elif opcion == "3":
            print("¡Hasta luego!")
            break
        else:
            print("Opción inválida")
