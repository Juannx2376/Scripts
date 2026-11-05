import hashlib

def identificar_hash(hash_texto):
    largos = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
        128: "SHA512",
    }
    tipo = largos.get(len(hash_texto))
    if tipo:
        print(f"El hash parece ser {tipo} longitud {len(hash_texto)}")
        return tipo
    else:
        print(f"No se reconoce un hash de longitud {len(hash_texto)}")
        return None

def hashear(palabra, tipo):
    palabra_bytes = palabra.encode()
    if tipo == "MD5":
        return hashlib.md5(palabra_bytes).hexdigest()
    elif tipo == "SHA1":
        return hashlib.sha1(palabra_bytes).hexdigest()
    elif tipo == "SHA256":
        return hashlib.sha256(palabra_bytes).hexdigest()
    elif tipo == "SHA512":
        return hashlib.sha512(palabra_bytes).hexdigest()
    else:
        return None

def crackear(hash_objetivo, wordlist):
    tipo = identificar_hash(hash_objetivo)
    if tipo is None:
        return None

    print(f"Probando {len(wordlist)} palabras...")
    for palabra in wordlist:
        if hashear(palabra, tipo) == hash_objetivo:
            print(f"Encontrado: La contraseña es: {palabra}")
            return palabra

    print("No se encontro en la lista")
    return None

COMUNES = ["123456", "password", "admin", "qwerty", "12345678", "hola", "iloveyou", "111111", "abc123", "root"]

def cargar_wordlist(ruta):
    try:
        with open(ruta, "r", encoding="latin-1", errors="ignore") as f:
            return [linea.strip() for linea in f]
    except FileNotFoundError:
        print("Archivo no encontrado, se usara lista corta")
        return COMUNES

if __name__ == "__main__":
    print("Hash Cracker")
    hash_objetivo = input("Hash a crackear: ").strip()

    ruta = input("Ruta de Wordlist (enter = lista corta): ").strip()
    if ruta:
        wordlist = cargar_wordlist(ruta)
    else:
        wordlist = COMUNES

    crackear(hash_objetivo, wordlist)

print