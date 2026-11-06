import time
import hmac
import hashlib
import base64
import struct

def contador_tiempo(intervalo=30):
    return int(time.time()) // intervalo

def generar_hmac(secreto, contador):
    clave = base64.b32decode(secreto, casefold=True)

    contador_bytes = struct.pack(">Q", contador)
    
    return hmac.new(clave, contador_bytes, hashlib.sha1).digest()

def generar_codigo(secreto, digitos=6):
    contador = contador_tiempo()
    h = generar_hmac(secreto, contador)

    offset = h[-1] & 0x0F

    trozo = h[offset:offset + 4]
    numero = struct.unpack(">I", trozo)[0]

    numero = numero & 0x7FFFFFFF

    codigo = numero % (10 ** digitos)

    return str(codigo).zfill(digitos)

def mostrar_en_vivo(secreto):
    print("Generando codigos (Ctrl+C para salir)\n")
    try:
        while True:
            codigo = generar_codigo(secreto)
            restante = 30 - (int(time.time()) % 30)
            print(f"\rCodigo: {codigo} | cambia en {restante:2d}s ", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("¡Regresa pronto!")

if __name__ == "__main__":
    print("Generador 2FA (TOTP)")
    secreto = input("Secreto (base32, enter = usar uno de ejemplo): ").strip()
    if not secreto:
        secreto ="JBSWY3DPEHPK3PXP"
        print(f"Usando secreto de ejemplo: {secreto}")
    mostrar_en_vivo(secreto)