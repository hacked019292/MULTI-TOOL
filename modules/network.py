"""
TraxerTool - modules/network.py
Herramientas de red: escaneo de puertos, WHOIS, DNS, headers de seguridad HTTP.
Todas las funciones están pensadas para uso ÉTICO sobre sistemas propios
o con autorización explícita.
"""

import socket
import ssl
import datetime
import concurrent.futures

from modules.ui import c, print_table, warn, ok, info

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def scan_port(host, port, timeout=0.8):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return port, result == 0
    except Exception:
        return port, False


def port_scanner(host, ports=None, timeout=0.8, max_workers=100):
    """Escaneo TCP connect simple. Úsalo solo en hosts propios o autorizados."""
    ip = resolve_host(host)
    if not ip:
        warn(f"No se pudo resolver el host: {host}")
        return []

    ports = ports or list(COMMON_PORTS.keys())
    info(f"Escaneando {host} ({ip}) — {len(ports)} puertos...")

    abiertos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(scan_port, ip, p, timeout) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                servicio = COMMON_PORTS.get(port, "Desconocido")
                abiertos.append((port, servicio))

    abiertos.sort()
    if abiertos:
        print_table(["Puerto", "Servicio"], [[str(p), s] for p, s in abiertos])
    else:
        warn("No se encontraron puertos abiertos en la lista analizada.")
    return abiertos


def whois_lookup(domain):
    """WHOIS básico usando sockets contra servidores whois públicos (sin libs externas)."""
    servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "dev": "whois.nic.google",
    }
    tld = domain.split(".")[-1].lower()
    server = servers.get(tld, "whois.iana.org")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((server, 43))
            s.send((domain + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode(errors="ignore")
    except Exception as e:
        warn(f"Error consultando WHOIS ({server}): {e}")
        return None


def dns_lookup(domain):
    """Resolución DNS básica (A record) + intento de reverse DNS."""
    resultados = {}
    try:
        resultados["A"] = socket.gethostbyname_ex(domain)
    except socket.gaierror as e:
        warn(f"No se pudo resolver {domain}: {e}")
        return resultados

    ip = resultados["A"][2][0]
    try:
        resultados["PTR"] = socket.gethostbyaddr(ip)
    except Exception:
        resultados["PTR"] = None

    return resultados


def check_tls_cert(host, port=443):
    """Revisa certificado TLS: emisor, validez y fecha de expiración."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        warn(f"No se pudo obtener el certificado: {e}")
        return None

    expira = cert.get("notAfter")
    if expira:
        fecha_exp = datetime.datetime.strptime(expira, "%b %d %H:%M:%S %Y %Z")
        dias_restantes = (fecha_exp - datetime.datetime.utcnow()).days
        if dias_restantes < 0:
            warn("¡El certificado ya expiró!")
        elif dias_restantes < 30:
            warn(f"El certificado expira pronto: {dias_restantes} días restantes.")
        else:
            ok(f"Certificado válido. Expira en {dias_restantes} días ({expira}).")
    issuer = dict(x[0] for x in cert.get("issuer", []))
    print_table(["Campo", "Valor"], [
        ["Dominio", host],
        ["Emisor", issuer.get("organizationName", "N/A")],
        ["Válido hasta", expira or "N/A"],
    ])
    return cert


def check_security_headers(url):
    """Analiza headers de seguridad HTTP comunes usando solo librerías estándar."""
    from urllib.request import urlopen, Request
    from urllib.error import URLError

    if not url.startswith("http"):
        url = "https://" + url

    headers_a_revisar = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    req = Request(url, headers={"User-Agent": "TraxerTool/1.0"})
    try:
        resp = urlopen(req, timeout=6)
        headers = dict(resp.headers)
    except URLError as e:
        warn(f"No se pudo conectar a {url}: {e}")
        return None

    filas = []
    for h in headers_a_revisar:
        presente = h in headers
        valor = headers.get(h, "— ausente —")
        filas.append([h, c("✓", "green") if presente else c("✗", "red"), valor[:50]])

    print_table(["Header", "¿Presente?", "Valor"], filas)
    return headers
