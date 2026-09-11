#!/bin/bash
# ReconX installer - makes 'reconx' available as a global command
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing ReconX..."
chmod +x "$SCRIPT_DIR/reconx.py"
sudo cp "$SCRIPT_DIR/reconx.py" /usr/local/bin/reconx

echo "[+] Installed! Try running: reconx --help"
