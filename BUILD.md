# Building the standalone demo binaries

The system runs from Python (`python bads.py ...`) on any OS. For a demo
machine without Python it can be packaged into one native binary per
platform, placed in `software/`:

| OS      | Binary                     | Build on |
| ------- | -------------------------- | -------- |
| Windows | `software/windows-demo.exe`| Windows  |
| Linux   | `software/linux-demo`      | Linux    |
| macOS   | `software/macos-demo`      | macOS    |

PyInstaller **cannot cross-compile** — each binary must be built on its
own OS.

## Windows

```powershell
pip install pyinstaller
python -m PyInstaller --onefile --noconfirm --name windows-demo `
    --distpath software `
    --collect-submodules sklearn --collect-submodules scipy bads.py
```

Produces `software\windows-demo.exe` (~95 MB — bundles scikit-learn,
pandas, matplotlib and the Python runtime). PyInstaller also writes
`windows-demo.spec` and a `build\` work folder; both are git-ignored.

## Linux / macOS

Run the helper on the target OS (produces `linux-demo` or `macos-demo`):

```bash
chmod +x software/build-standalone.sh
./software/build-standalone.sh
```

Until then, `software/linux-demo` / `software/macos-demo` run the app
from source (need Python + `requirements.txt`).

## Run

Each binary finds the project folder automatically (walks up from its own
location for `demo/` + `config/`), so it works from anywhere as long as it
stays in `software/` under the project. No argument shows the menu; or:

```
software/windows-demo.exe analyze      # sample-data report
software/windows-demo.exe demo         # full run + dashboard
software/windows-demo.exe evaluate     # metrics + confusion matrix + ROC
software/windows-demo.exe benchmark    # NSL-KDD benchmark
software/windows-demo.exe --help
```

(`./software/linux-demo ...` / `./software/macos-demo ...` on those OSes.)

Live scanning (`own` / `watch`) needs elevation to read the security log:
Administrator on Windows, `sudo` on Linux (auth.log + auditd) / macOS
(unified log). Logs go to `logs/bads.log`; set `BADS_DEBUG=1` for console
INFO logs.
