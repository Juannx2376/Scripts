from PIL import Image

def texto_a_bits(texto):
    bits = ""
    for caracter in texto:
        bits += format(ord(caracter), "08b")
    return bits

def bits_a_texto(bits):
    texto = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        texto += chr(int(byte, 2))
    return texto

MARCADOR = "1111111111111110"

def ocultar(ruta_imagen, mensaje, ruta_salida):
    if not ruta_salida.lower().endswith(".png"):
        ruta_salida += ".png"
    imagen = Image.open(ruta_imagen)
    imagen = imagen.convert("RGB")
    pixeles = imagen.load()
    ancho, alto = imagen.size

    bits = texto_a_bits(mensaje) + MARCADOR
    indice = 0

    for y in range(alto):
        for x in range(ancho):
            r, g, b = pixeles[x, y]

            if indice < len(bits):
                r = (r & ~1) | int(bits[indice])
                indice += 1
            if indice < len(bits):
                g = (g & ~1) | int(bits[indice])
                indice += 1
            if indice < len(bits):
                b = (b & ~1) | int(bits[indice])
                indice += 1

            pixeles[x, y] = (r, g, b)

            if indice >= len(bits):
                imagen.save(ruta_salida)
                print(f"Mensaje oculto en {ruta_salida}")
                return

    print("La imagen es muy pequeña para este mensaje")

def revelar(ruta_imagen):
    imagen = Image.open(ruta_imagen).convert("RGB")
    pixeles = imagen.load()
    ancho, alto = imagen.size

    bits = ""
    for y in range(alto):
        for x in range(ancho):
            r, g, b =pixeles[x, y]
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

            if MARCADOR in bits:
                bits = bits[:bits.index(MARCADOR)]
                mensaje = bits_a_texto(bits)
                print(f"Mensaje oculto: {mensaje}")
                return mensaje

    print("No se encontró ningún mensaje")

if __name__ == "__main__":
    while True:
        print("Esteganografia")
        print("1 - Ocultar mensaje en una imagen")
        print("2 - Revelar mensaje de una imagen")
        print("3 - Salir")

        opcion = input("Selecciona una opcion: ")

        if opcion == "1":
            ruta_imagen = input("Ruta de la imagen: ")
            mensaje = input("Mensaje a ocultar: ")
            ruta_salida = input("Nombre de la imagen de salida: ")
            ocultar(ruta_imagen, mensaje, ruta_salida)
        elif opcion == "2":
            ruta_imagen = input("Ruta de la imagen con el mensaje: ")
            revelar(ruta_imagen)
        elif opcion == "3":
            print("Saliendo...")
            break
        else:
            print("Opcion invalida")