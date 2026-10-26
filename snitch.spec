# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a single-file SNItch executable.

Usage (from the repository root):

    python -m pip install pyinstaller
    pyinstaller snitch.spec --noconfirm

The executable lands in ``dist/``.  The dashboard template and the world map
data are bundled inside it; results are written next to the executable.
"""

import os

ROOT = os.path.abspath(os.getcwd())

datas = [
    (os.path.join(ROOT, "snitchlib", "templates", "dashboard.html"),
     os.path.join("snitchlib", "templates")),
    (os.path.join(ROOT, "snitchlib", "world.geo.json"), "snitchlib"),
]

a = Analysis(
    ["snitch.py"],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter.test", "test", "unittest", "pydoc_data"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="snitch",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
