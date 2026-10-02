"""
TraxerTool - modules/osint.py
Reconocimiento pasivo: enumeración de subdominios vía Certificate
Transparency (crt.sh) y geolocalización de IP vía ip-api.com.
Solo usa fuentes públicas y pasivas, sin tocar directamente el objetivo.
"""

import json
import urllib.request
import urllib.parse

from modules.ui import print_table, warn, info, ok


def _http_get_json(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "TraxerTool/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        return json.loads(data)
    except Exception as e:
        warn(f"Error en la petición: {e}")
        return None


def subdomain_enum(domain):
    """Enumeración PASIVA de subdominios usando certificados públicos (crt.sh)."""
    info(f"Buscando subdominios de {domain} en Certificate Transparency logs...")
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    data = _http_get_json(url)
    if not data:
        warn("No se obtuvieron resultados (crt.sh puede estar caído o saturado).")
        return []

    subs = set()
    for entry in data:
        nombre = entry.get("name_value", "")
        for linea in nombre.split("\n"):
            linea = linea.strip().lower()
            if linea and "*" not in linea:
                subs.add(linea)

    subs = sorted(subs)
    if subs:
        ok(f"Se encontraron {len(subs)} subdominios únicos.")
        for s in subs:
            print(f"  - {s}")
    else:
        warn("No se encontraron subdominios.")
    return subs


def ip_geolocation(ip_or_host):
    """Geolocalización aproximada de una IP/host vía ip-api.com (uso gratuito, sin API key)."""
    url = f"http://ip-api.com/json/{urllib.parse.quote(ip_or_host)}?lang=es"
    data = _http_get_json(url)
    if not data or data.get("status") != "success":
        warn(f"No se pudo geolocalizar: {data.get('message') if data else 'sin respuesta'}")
        return None

    print_table(["Campo", "Valor"], [
        ["IP", data.get("query", "N/A")],
        ["País", data.get("country", "N/A")],
        ["Región", data.get("regionName", "N/A")],
        ["Ciudad", data.get("city", "N/A")],
        ["ISP", data.get("isp", "N/A")],
        ["Organización", data.get("org", "N/A")],
        ["Zona horaria", data.get("timezone", "N/A")],
        ["Lat/Lon", f"{data.get('lat')}, {data.get('lon')}"],
    ])
    return data


def email_breach_hint(email):
    """
    No realiza consultas a APIs de terceros que requieran clave.
    Da orientación al usuario sobre cómo verificar si su correo fue
    comprometido en filtraciones conocidas, de forma responsable.
    """
    info("TraxerTool no almacena ni consulta tu correo en bases externas automáticamente.")
    print("Para revisar si tu correo apareció en alguna filtración conocida, visita:")
    print("  - https://haveibeenpwned.com")
    print("  - https://monitor.firefox.com")
    print("Nunca pegues contraseñas reales en formularios de terceros no verificados.")
