#!/usr/bin/env bash
# Launcher for Linux/macOS (equivalent to run.bat on Windows)
cd "$(dirname "$0")"
python3 snitch.py "$@"
