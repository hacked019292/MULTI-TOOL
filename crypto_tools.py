"""
TraxerTool - modules/crypto_tools.py
Hashing, verificación de integridad, análisis de fortaleza de contraseñas
y generación de contraseñas seguras. Sin dependencias externas.
"""

import hashlib
import secrets
import string
import math
import re

from modules.ui import print_table, ok, warn, info


def hash_text(text, algorithm="sha256"):
    algorithm = algorithm.lower()
    if algorithm not in hashlib.algorithms_available:
        warn(f"Algoritmo no soportado: {algorithm}")
        return None
    h = hashlib.new(algorithm)
    h.update(text.encode())
    return h.hexdigest()


def hash_all(text):
    algos = ["md5", "sha1", "sha256", "sha512"]
    filas = [[a.upper(), hash_text(text, a)] for a in algos]
    print_table(["Algoritmo", "Hash"], filas)


def hash_file(filepath, algorithm="sha256"):
    algorithm = algorithm.lower()
    if algorithm not in hashlib.algorithms_available:
        warn(f"Algoritmo no soportado: {algorithm}")
        return None
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except FileNotFoundError:
        warn(f"Archivo no encontrado: {filepath}")
        return None
    return h.hexdigest()


def verify_integrity(filepath, expected_hash, algorithm="sha256"):
    resultado = hash_file(filepath, algorithm)
    if resultado is None:
        return False
    coincide = resultado.lower() == expected_hash.lower().strip()
    if coincide:
        ok("✓ El hash coincide. El archivo es íntegro.")
    else:
        warn("✗ El hash NO coincide. El archivo pudo ser alterado.")
        info(f"Calculado: {resultado}")
        info(f"Esperado : {expected_hash}")
    return coincide


def password_entropy(password):
    """Calcula la entropía aproximada en bits según el conjunto de caracteres usado."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    if pool == 0:
        return 0
    return len(password) * math.log2(pool)


def check_password_strength(password):
    entropia = password_entropy(password)
    longitud = len(password)

    comunes = {
        "123456", "password", "12345678", "qwerty", "abc123",
        "111111", "123123", "admin", "letmein", "welcome",
        "iloveyou", "contraseña", "12345", "123456789",
    }

    problemas = []
    if longitud < 8:
        problemas.append("Muy corta (mínimo recomendado: 12 caracteres)")
    if password.lower() in comunes:
        problemas.append("¡Está en listas de contraseñas filtradas/comunes!")
    if not re.search(r"[A-Z]", password):
        problemas.append("Sin mayúsculas")
    if not re.search(r"[a-z]", password):
        problemas.append("Sin minúsculas")
    if not re.search(r"[0-9]", password):
        problemas.append("Sin números")
    if not re.search(r"[^a-zA-Z0-9]", password):
        problemas.append("Sin símbolos")

    if entropia < 28:
        nivel = c_level("Muy débil", "red")
    elif entropia < 36:
        nivel = c_level("Débil", "red")
    elif entropia < 60:
        nivel = c_level("Razonable", "yellow")
    elif entropia < 80:
        nivel = c_level("Fuerte", "green")
    else:
        nivel = c_level("Muy fuerte", "green")

    print_table(["Métrica", "Valor"], [
        ["Longitud", str(longitud)],
        ["Entropía estimada", f"{entropia:.1f} bits"],
        ["Nivel", nivel],
    ])

    if problemas:
        warn("Puntos a mejorar:")
        for p in problemas:
            print(f"  - {p}")
    else:
        ok("No se detectaron debilidades evidentes.")

    return entropia


def c_level(text, color):
    from modules.ui import c
    return c(text, color)


def generate_password(length=16, use_symbols=True):
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{}"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_passphrase(num_words=5):
    """Genera una passphrase tipo diceware con una mini wordlist embebida.
    Para uso real se recomienda una wordlist EFF completa."""
    wordlist = [
        "atomo", "bosque", "cactus", "delfin", "eco", "fuego", "galaxia",
        "huracan", "iman", "jaguar", "kilo", "luna", "montana", "nube",
        "oceano", "planeta", "quasar", "rio", "sol", "tigre", "universo",
        "volcan", "web", "xenon", "yunque", "zafiro", "aurora", "brisa",
        "cometa", "dragon",
    ]
    return "-".join(secrets.choice(wordlist) for _ in range(num_words))


def base64_tools(text, mode="encode"):
    import base64
    try:
        if mode == "encode":
            return base64.b64encode(text.encode()).decode()
        else:
            return base64.b64decode(text.encode()).decode()
    except Exception as e:
        warn(f"Error procesando Base64: {e}")
        return None
