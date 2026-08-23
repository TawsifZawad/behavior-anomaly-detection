# software — runnable demos

Per-platform entry points for the Behavior Anomaly Detection System.
All read the same project (`demo/`, `data/`, `ml/`, `config/`) in the
parent folder, so keep this folder inside the project.

| Platform | File                  | How to run                              | Standalone? |
| -------- | --------------------- | --------------------------------------- | ----------- |
| Windows  | `windows-demo.exe`    | double-click, or `windows-demo.exe`     | ✅ yes (no Python) |
| Linux    | `linux-demo`          | `./linux-demo`  (`sudo ./linux-demo own`) | ⚠️ needs Python* |
| macOS    | `macos-demo`          | `./macos-demo`  (`sudo ./macos-demo own`) | ⚠️ needs Python* |

No argument → the menu: **[1] Own** (scan this machine), **[2] Analyze**
(sample data), **[3] Live** (continuous). Or pass a command:
`analyze`, `own`, `watch`, `evaluate`, `benchmark`, `dashboard`.

\* PyInstaller cannot cross-compile, so the Windows `.exe` is built on
Windows and the Linux/macOS launchers run from the Python source. To get
a **true standalone binary** (no Python needed) on Linux or macOS, run
this **on that OS**:

```bash
chmod +x software/linux-demo software/macos-demo software/build-standalone.sh
./software/build-standalone.sh      # -> software/linux-demo or software/macos-demo (standalone)
```

Live scanning (`own` / `watch`) needs elevated rights to read the
security log: **Administrator** on Windows, **root/sudo** on Linux
(auth.log + auditd) and macOS (unified log / eslogger).
