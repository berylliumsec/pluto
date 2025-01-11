# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

additional_files = [
    (r'pluto.py', '.'),
    (r'pluto/certificate.pem', '.')
]
binaries = [
    (r'pluto/pluto_dist/pluto/web_socket_client.cp311-win_amd64.pyd', '.'),
    (r'pluto/pluto_dist/pluto/terminal_client.cp311-win_amd64.pyd', '.'),
    (r'pluto/pluto_dist/pluto/transformer.cp311-win_amd64.pyd', '.'),

]

# Collect data files from specific modules if needed
datas = collect_data_files('pluto')  # Replace 'pluto' with actual module name if needed
datas += additional_files

a = Analysis(
    ['pluto.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=[
    'subprocess', 
    'logging', 
    'typing', 
    'threading', 
    'multiprocessing',
    'websockets',
    'PyQt6',
    'backoff',
    'ctypes',
    'ctypes.wintypes',
    'numpy',
    'cv2'
],

    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='pluto_windows',
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
