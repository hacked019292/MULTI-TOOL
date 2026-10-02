"""
TraxerTool - coremods/vuln_scan.py
Detección PASIVA de vulnerabilidades y malas configuraciones:
  - Banner grabbing (identificar software/versión de un servicio)
  - Búsqueda de CVEs conocidos por palabra clave/versión (API pública NVD)
  - Chequeo de exposición de archivos/rutas sensibles comunes
  - Chequeo de configuración TLS/cifrados débiles (aprovecha network.py)

IMPORTANTE: Este módulo NO explota nada. Solo observa respuestas públicas
de un servicio (banners, headers, códigos HTTP) y compara con bases de
datos públicas de CVEs. Úsalo solo en sistemas propios o autorizados.
"""

import socket
import json
import urllib.request
import urllib.parse
import urllib.error

from coremods.ui import print_table, warn, info, ok, c

# Rutas comunes que, si quedan expuestas sin autenticación, suelen indicar
# una mala configuración (no es un ataque, solo se pide la URL como
# cualquier navegador lo haría).
RUTAS_SENSIBLES = [
    "/.git/config",
    "/.env",
    "/.env.local",
    "/wp-config.php.bak",
    "/backup.zip",
    "/backup.sql",
    "/phpinfo.php",
    "/.DS_Store",
    "/server-status",
    "/.htpasswd",
    "/admin/",
    "/.well-known/security.txt",
]


def banner_grab(host, port, timeout=4):
    """Se conecta a un puerto TCP y lee lo primero que el servicio anuncia
    (banner). Muchos servicios (FTP, SSH, SMTP, HTTP) revelan su versión
    exacta aquí, lo cual es la primera pista para saber si hay un CVE
    conocido para esa versión."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (80, 8080, 443, 8443):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner
    except Exception as e:
        warn(f"No se pudo obtener banner de {host}:{port} ({e})")
        return None


def banner_scan(host, ports):
    """Hace banner grabbing sobre una lista de puertos y muestra resultados."""
    filas = []
    for port in ports:
        banner = banner_grab(host, port)
        if banner:
            primera_linea = banner.split("\n")[0][:70]
            filas.append([str(port), primera_linea])
    if filas:
        print_table(["Puerto", "Banner (primera línea)"], filas)
    else:
        warn("No se obtuvieron banners en los puertos indicados.")
    return filas


def buscar_cves(keyword, resultados_max=8):
    """Busca CVEs públicos relacionados a un software/versión usando la
    API oficial del NVD (National Vulnerability Database, de NIST).
    Ejemplo de keyword: 'Apache 2.4.49' o 'OpenSSH 7.2'.
    """
    info(f"Buscando CVEs públicos para: {keyword} ...")
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage={resultados_max}"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "TraxerTool/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        warn(f"El NVD respondió con error {e.code}. Intenta de nuevo en unos segundos "
             f"(la API pública tiene límite de peticiones).")
        return []
    except Exception as e:
        warn(f"No se pudo consultar el NVD: {e}")
        return []

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        warn("No se encontraron CVEs para esa búsqueda.")
        return []

    filas = []
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descripciones = cve.get("descriptions", [])
        desc_es_en = next((d["value"] for d in descripciones if d.get("lang") == "en"), "")
        severidad = "N/A"
        metrics = cve.get("metrics", {})
        for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if clave in metrics and metrics[clave]:
                severidad = str(metrics[clave][0]["cvssData"].get("baseScore", "N/A"))
                break
        filas.append([cve_id, severidad, desc_es_en[:80] + ("..." if len(desc_es_en) > 80 else "")])

    print_table(["CVE", "Score CVSS", "Descripción"], filas)
    ok(f"Se encontraron {len(vulns)} resultado(s). Consulta cada CVE en https://nvd.nist.gov/vuln/detail/<CVE-ID>")
    return filas


def check_exposed_paths(base_url, rutas=None, timeout=5):
    """Revisa si rutas/archivos sensibles comunes están expuestos
    públicamente (solo hace peticiones GET normales, como un navegador)."""
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")
    rutas = rutas or RUTAS_SENSIBLES

    info(f"Revisando {len(rutas)} rutas sensibles comunes en {base_url} ...")
    encontrados = []
    for ruta in rutas:
        url = base_url + ruta
        req = urllib.request.Request(url, headers={"User-Agent": "TraxerTool/1.0"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                codigo = resp.status
        except urllib.error.HTTPError as e:
            codigo = e.code
        except Exception:
            continue

        if codigo == 200:
            encontrados.append((ruta, codigo))

    if encontrados:
        warn(f"¡Atención! {len(encontrados)} ruta(s) sensible(s) accesible(s):")
        print_table(["Ruta", "Código HTTP"], [[r, str(cod)] for r, cod in encontrados])
        warn("Si este es tu sitio, revisa la configuración del servidor para bloquear el acceso.")
    else:
        ok("No se encontraron rutas sensibles expuestas de la lista revisada.")
    return encontrados


def full_vuln_report(host):
    """Reporte combinado: banners de puertos web comunes + rutas sensibles."""
    print(c(f"\n=== Reporte de vulnerabilidades pasivo: {host} ===", "bold"))
    banner_scan(host, [80, 443, 21, 22, 25])
    check_exposed_paths(host)
