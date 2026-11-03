import socket
import threading
import hashlib
import base64
from cryptography.fernet import Fernet

def crear_llave(password):
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def recibir_mensajes(conexion, fernet):
    while True:
        try:
            datos = conexion.recv(4096)
            if not datos:
                print("La otra persona se desconecto")
                break
            mensaje = fernet.decrypt(datos).decode()
            print(f"\n[Otro]: {mensaje}")
        except Exception:
            break

def chatear(conexion, password):
    fernet = Fernet(crear_llave(password))

    hilo = threading.Thread(target=recibir_mensajes, args=(conexion, fernet), daemon=True)
    hilo.start()
    while True:
        texto = input()
        if texto.lower() == "salir":
            break
        cifrado = fernet.encrypt(texto.encode())
        conexion.send(cifrado)

    conexion.close()

def modo_servidor(password):
    puerto = 9999
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind(("0.0.0.0", puerto))
    servidor.listen(1)
    print(f"Esperando conexion al puerto {puerto}...")

    conexion, direccion = servidor.accept()
    print(f"Conectado con {direccion}")
    chatear(conexion, password)

def modo_cliente(password):
    ip = input("IP del servidor: ")
    puerto = 9999
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.connect((ip, puerto))
    chatear(cliente, password)

if __name__ == "__main__":
    print("Chat Cifrado")
    print("1 - Crear sala (servidor)")
    print("2 - Unirse a sala (cliente)")
    opcion = input("Selecciona una opcion: ")

    password = input("Contraseña compartida del chat: ")
    
    if opcion == "1":
        modo_servidor(password)
    elif opcion == "2":
        modo_cliente(password)
    else:
        print("Opcion invalida")