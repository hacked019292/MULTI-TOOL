#!/usr/bin/env bash
# install.sh - Instalador de TraxerTool para Termux, Kali Linux, Debian/Ubuntu
set -e

echo "============================================="
echo "   Instalando TraxerTool - comunidad Traxer"
echo "============================================="

# Detectar si estamos en Termux
if [ -n "$PREFIX" ] && [[ "$PREFIX" == *"com.termux"* ]]; then
    echo "[*] Entorno Termux detectado."
    pkg update -y
    pkg install -y python git
else
    echo "[*] Entorno Linux estándar detectado (Kali/Debian/Ubuntu)."
    if command -v apt >/dev/null 2>&1; then
        sudo apt update -y
        sudo apt install -y python3 python3-pip git
    fi
fi

# Verificar Python
if ! command -v python3 >/dev/null 2>&1; then
    echo "[x] No se encontró python3. Instálalo manualmente e inténtalo de nuevo."
    exit 1
fi

echo "[*] Dando permisos de ejecución a traxer.py..."
chmod +x traxer.py

echo "[*] Creando acceso directo 'traxer' (opcional)..."
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/traxer" <<EOF
#!/usr/bin/env bash
python3 "$(pwd)/traxer.py" "\$@"
EOF
chmod +x "$BIN_DIR/traxer"

echo ""
echo "✅ Instalación completa."
echo ""
echo "Ejecuta la herramienta con:"
echo "   python3 traxer.py"
echo ""
echo "O, si agregaste '$BIN_DIR' a tu PATH, simplemente con:"
echo "   traxer"
echo ""
echo "Si '$BIN_DIR' no está en tu PATH, agrega esta línea a tu ~/.bashrc o ~/.zshrc:"
echo '   export PATH="$HOME/.local/bin:$PATH"'
