#!/usr/bin/env python3
"""
TraxerTool - Multitool de Ciberseguridad y Hacking Ético
Comunidad: Traxer (YouTube)

Compatible con Termux, Kali Linux, Debian/Ubuntu y cualquier Linux con
Python 3.8+. Solo usa librerías estándar, por lo que no requiere
instalar dependencias para funcionar (salvo 'requests' opcional).

AVISO LEGAL:
Esta herramienta está diseñada con fines educativos y de seguridad
defensiva/ofensiva ÉTICA. Úsala únicamente sobre sistemas, redes o
dominios de tu propiedad, o para los que tengas autorización explícita
por escrito. El autor y la comunidad Traxer no se hacen responsables
del mal uso de esta herramienta.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.ui import print_banner, ask, pause, error, info, ok, warn, c
from modules import network, crypto_tools, osint


def menu_red():
    while True:
        print(c("\n── RED Y RECONOCIMIENTO ──", "bold"))
        print(" 1) Escáner de puertos (TCP connect)")
        print(" 2) Consulta WHOIS")
        print(" 3) Resolución DNS / Reverse DNS")
        print(" 4) Revisar certificado TLS/SSL")
        print(" 5) Analizar headers de seguridad HTTP")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            host = ask("Host o IP objetivo")
            puertos_raw = ask("Puertos (ENTER = top comunes, ej '22,80,443' o '1-1000')")
            ports = None
            if puertos_raw:
                ports = parse_ports(puertos_raw)
            network.port_scanner(host, ports)
        elif op == "2":
            dominio = ask("Dominio (ej. ejemplo.com)")
            resultado = network.whois_lookup(dominio)
            if resultado:
                print(resultado)
        elif op == "3":
            dominio = ask("Dominio a resolver")
            res = network.dns_lookup(dominio)
            if res.get("A"):
                nombre, alias, ips = res["A"]
                print(c(f"\nHost: {nombre}", "green"))
                print(f"IPs: {', '.join(ips)}")
            if res.get("PTR"):
                print(f"PTR (reverse): {res['PTR'][0]}")
        elif op == "4":
            host = ask("Host (sin https://)")
            network.check_tls_cert(host)
        elif op == "5":
            url = ask("URL a analizar")
            network.check_security_headers(url)
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def parse_ports(raw):
    ports = set()
    for parte in raw.split(","):
        parte = parte.strip()
        if "-" in parte:
            try:
                a, b = parte.split("-")
                ports.update(range(int(a), int(b) + 1))
            except ValueError:
                continue
        elif parte.isdigit():
            ports.add(int(parte))
    return sorted(ports) if ports else None


def menu_cripto():
    while True:
        print(c("\n── CRIPTOGRAFÍA Y CONTRASEÑAS ──", "bold"))
        print(" 1) Generar hash de un texto (MD5/SHA1/SHA256/SHA512)")
        print(" 2) Calcular hash de un archivo")
        print(" 3) Verificar integridad de un archivo contra un hash")
        print(" 4) Analizar fortaleza de una contraseña")
        print(" 5) Generar contraseña segura")
        print(" 6) Generar passphrase (estilo diceware)")
        print(" 7) Codificar / Decodificar Base64")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            texto = ask("Texto a hashear")
            crypto_tools.hash_all(texto)
        elif op == "2":
            ruta = ask("Ruta del archivo")
            algo = ask("Algoritmo (sha256/md5/sha1/sha512) [sha256]") or "sha256"
            h = crypto_tools.hash_file(ruta, algo)
            if h:
                ok(f"{algo.upper()}: {h}")
        elif op == "3":
            ruta = ask("Ruta del archivo")
            hash_esperado = ask("Hash esperado")
            algo = ask("Algoritmo [sha256]") or "sha256"
            crypto_tools.verify_integrity(ruta, hash_esperado, algo)
        elif op == "4":
            pwd = ask("Contraseña a analizar (no se guarda ni se envía a ningún lado)")
            crypto_tools.check_password_strength(pwd)
        elif op == "5":
            try:
                longitud = int(ask("Longitud [16]") or "16")
            except ValueError:
                longitud = 16
            simbolos = ask("¿Incluir símbolos? (s/n) [s]") or "s"
            pwd = crypto_tools.generate_password(longitud, simbolos.lower() != "n")
            ok(f"Contraseña generada: {pwd}")
        elif op == "6":
            try:
                n = int(ask("Número de palabras [5]") or "5")
            except ValueError:
                n = 5
            ok(f"Passphrase: {crypto_tools.generate_passphrase(n)}")
        elif op == "7":
            modo = ask("¿Codificar o decodificar? (c/d)")
            texto = ask("Texto")
            resultado = crypto_tools.base64_tools(
                texto, "encode" if modo.lower().startswith("c") else "decode"
            )
            if resultado is not None:
                ok(f"Resultado: {resultado}")
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_osint():
    while True:
        print(c("\n── OSINT (RECON PASIVO) ──", "bold"))
        print(" 1) Enumerar subdominios (Certificate Transparency)")
        print(" 2) Geolocalizar IP / host")
        print(" 3) ¿Mi correo fue filtrado? (guía responsable)")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            dominio = ask("Dominio (ej. ejemplo.com)")
            osint.subdomain_enum(dominio)
        elif op == "2":
            host = ask("IP o host")
            osint.ip_geolocation(host)
        elif op == "3":
            email = ask("Tu correo (no se envía a ningún servidor)")
            osint.email_breach_hint(email)
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_principal():
    while True:
        print_banner()
        print(c("\n  MENÚ PRINCIPAL", "bold"))
        print("  1) 🌐 Red y Reconocimiento")
        print("  2) 🔐 Criptografía y Contraseñas")
        print("  3) 🕵️  OSINT (reconocimiento pasivo)")
        print("  4) ℹ️  Acerca de / Aviso legal")
        print("  0) 🚪 Salir")
        op = ask("Elige una opción")

        if op == "1":
            menu_red()
        elif op == "2":
            menu_cripto()
        elif op == "3":
            menu_osint()
        elif op == "4":
            mostrar_acerca_de()
            pause()
        elif op == "0":
            info("¡Gracias por usar TraxerTool! Nos vemos en el canal 🎬")
            sys.exit(0)
        else:
            error("Opción inválida")


def mostrar_acerca_de():
    print(c("\nTraxerTool v1.0", "bold"))
    print("Multitool de ciberseguridad creada para la comunidad Traxer.")
    print("Solo usa librerías estándar de Python — funciona en Termux, Kali,")
    print("Debian, Ubuntu, Arch, WSL, etc. con Python 3.8+.")
    warn("\nUso ético solamente: nunca la uses contra sistemas sin autorización.")
    print("Repo: https://github.com/<tu-usuario>/TraxerTool")


if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print()
        info("Saliendo... ¡Hasta la próxima!")
        sys.exit(0)
