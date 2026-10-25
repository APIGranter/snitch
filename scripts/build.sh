#!/usr/bin/env bash
# Build a single-file SNItch executable with PyInstaller (Linux/macOS).
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pip install --upgrade pyinstaller
python3 -m PyInstaller snitch.spec --noconfirm --clean

echo
echo "Built: $(pwd)/dist/snitch"
echo "Run:   ./dist/snitch --help"
