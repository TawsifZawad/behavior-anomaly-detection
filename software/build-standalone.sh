#!/usr/bin/env bash
# Build a TRUE standalone binary for the CURRENT operating system.
#
# PyInstaller cannot cross-compile, so a native Linux binary must be
# built on Linux and a native macOS binary on macOS. Run this script on
# the target OS; it produces:
#
#     software/linux-demo   (when run on Linux)
#     software/macos-demo   (when run on macOS)
#
# The Windows build (software/windows-demo.exe) is produced on Windows
# with the equivalent PyInstaller command (see ../BUILD.md).
set -e
cd "$(dirname "$0")/.."

case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
  linux*)  NAME=linux-demo ;;
  darwin*) NAME=macos-demo ;;
  *) echo "Run this on Linux or macOS (Windows uses BUILD.md)."; exit 1 ;;
esac

python3 -m pip install -r requirements.txt pyinstaller
python3 -m PyInstaller --onefile --noconfirm --name "$NAME" \
  --distpath software \
  --collect-submodules sklearn --collect-submodules scipy \
  bads.py

echo "Built: software/$NAME"
