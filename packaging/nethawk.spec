# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for NetHawk.

Build (from the project root, inside the virtual environment):

    pyinstaller packaging/nethawk.spec --noconfirm

Produces dist/NetHawk/NetHawk - a one-directory bundle that keeps the console
attached, so both the dashboard and the CLI flags (--replay, --headless,
--paths) work from the same executable.

The bundle is read-only, so at runtime NetHawk writes its database, model,
logs and demo data to ~/Library/Application Support/NetHawk (see
src/nethawk/config.py).  The trained model and demo data shipped here are
copied into that directory on first launch.
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PROJECT_ROOT = Path(SPECPATH).parent

# Ship the trained model and the demo/sample data so the first launch is
# instant instead of training on startup.  Each entry is optional: the build
# still succeeds (and the app self-generates) when a file is absent.
_optional = [
    ("models/nethawk_rf.joblib", "models"),
    ("models/metrics.json", "models"),
    ("data/demo/nethawk_demo_traffic.csv", "data/demo"),
    ("data/demo/sample_traffic.pcap", "data/demo"),
    ("data/README.md", "data"),
    ("README.md", "."),
]
datas = [(str(PROJECT_ROOT / rel), dest)
         for rel, dest in _optional if (PROJECT_ROOT / rel).exists()]
datas += collect_data_files("customtkinter")

hiddenimports = [
    "sklearn.ensemble._forest",
    "sklearn.tree._classes",
    "sklearn.utils._typedefs",
    "sklearn.utils._heap",
    "sklearn.utils._sorting",
    "sklearn.utils._vector_sentinel",
    "sklearn.neighbors._partition_nodes",
]
# Scapy resolves protocol layers dynamically, so they must be pulled in.
hiddenimports += collect_submodules("scapy.layers")
hiddenimports += ["scapy.arch.common"]

a = Analysis(
    [str(PROJECT_ROOT / "app.py")],
    pathex=[str(PROJECT_ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["PyQt5", "PyQt6", "PySide2", "PySide6", "matplotlib",
              "IPython", "jupyter", "notebook", "sphinx"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NetHawk",
    debug=False,
    strip=False,
    upx=False,
    console=True,          # keep the console so the CLI flags remain usable
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="NetHawk",
)
