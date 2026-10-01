# 🛡️ TraxerTool

Multitool de **ciberseguridad y hacking ético** creada para la comunidad de YouTube **Traxer**.

Funciona en **Termux**, **Kali Linux**, **Debian/Ubuntu**, **Arch**, **WSL** y cualquier sistema con Python 3.8+. No necesita dependencias externas: todo corre con la librería estándar de Python.

```
 _______                          _____           _
|__   __|                        |_   _|         | |
   | |_ __ __ ___  _____ _ __      | |  ___   ___ | |
   | | '__/ _` \ \/ / _ \ '__|     | | / _ \ / _ \| |
   | | | | (_| |>  <  __/ |       _| || (_) | (_) | |
   |_|_|  \__,_/_/\_\___|_|      |_____\___/ \___/|_|
```

## ⚠️ Aviso legal

TraxerTool se entrega **exclusivamente con fines educativos y de seguridad ética**. Úsala solo sobre sistemas, redes o dominios de tu propiedad, o cuando tengas **autorización explícita por escrito** del propietario. El autor y la comunidad Traxer no se hacen responsables del mal uso de esta herramienta. Escanear o atacar sistemas sin permiso es **ilegal** en la mayoría de los países.

## ✨ Funciones incluidas

### 🌐 Red y reconocimiento
- Escáner de puertos TCP (multihilo, puertos comunes o rango personalizado)
- Consulta WHOIS de dominios
- Resolución DNS y reverse DNS (PTR)
- Revisión de certificados TLS/SSL (emisor, caducidad)
- Analizador de headers de seguridad HTTP (HSTS, CSP, X-Frame-Options, etc.)

### 🔐 Criptografía y contraseñas
- Generador de hash (MD5, SHA1, SHA256, SHA512) de texto o archivos
- Verificador de integridad de archivos contra un hash conocido
- Analizador de fortaleza de contraseñas (entropía, debilidades, lista de comunes)
- Generador de contraseñas seguras
- Generador de passphrases estilo diceware
- Codificador/decodificador Base64

### 🕵️ OSINT (reconocimiento pasivo)
- Enumeración de subdominios vía Certificate Transparency (crt.sh)
- Geolocalización aproximada de IP/host
- Guía responsable para verificar filtraciones de correo (HaveIBeenPwned, etc.)

## 📦 Instalación

### Termux
```bash
pkg update && pkg install python git -y
git clone https://github.com/<tu-usuario>/TraxerTool.git
cd TraxerTool
bash install.sh
python3 traxer.py
```

### Kali Linux / Debian / Ubuntu
```bash
sudo apt update && sudo apt install python3 git -y
git clone https://github.com/<tu-usuario>/TraxerTool.git
cd TraxerTool
bash install.sh
python3 traxer.py
```

### Manual (cualquier sistema con Python 3.8+)
```bash
git clone https://github.com/<tu-usuario>/TraxerTool.git
cd TraxerTool
python3 traxer.py
```

## 🚀 Uso

Al ejecutar `python3 traxer.py` verás un menú interactivo dividido en tres secciones (Red, Criptografía, OSINT). Navega con los números y sigue las instrucciones en pantalla.

## 📁 Estructura del proyecto

```
TraxerTool/
├── traxer.py              # Punto de entrada / menú principal
├── install.sh             # Instalador para Termux/Kali/Debian
├── requirements.txt
├── README.md
└── modules/
    ├── ui.py               # Colores, banner, tablas
    ├── network.py          # Escaneo de puertos, WHOIS, DNS, TLS, headers
    ├── crypto_tools.py     # Hashing, contraseñas, Base64
    └── osint.py            # Subdominios, geolocalización IP
```

## 🤝 Contribuir

¿Tienes una idea para un nuevo módulo ético (defensivo o de recon pasivo)? Abre un *issue* o un *pull request*. Las contribuciones que automaticen ataques activos sin consentimiento (fuerza bruta, explotación, malware) **no serán aceptadas**.

## 📺 Comunidad

Creado para y por la comunidad de **Traxer** en YouTube. Síguenos para más contenido de ciberseguridad y hacking ético.

## 📄 Licencia

MIT — úsala, modifícala y compártela libremente, siempre de forma ética.
