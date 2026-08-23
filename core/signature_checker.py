import os
import platform
import subprocess
from functools import lru_cache


@lru_cache(maxsize=256)
def check_signature(path):
    """
    Authenticode signature check for a Windows executable.

    Returns:
        True  -> validly signed
        False -> unsigned or invalid signature
        None  -> could not determine (non-Windows, file missing,
                 check failed) — callers must NOT treat this as unsigned.

    Only called for executables that already look suspicious
    (SIGNATURE_CHECK_TRIGGERS in specs/process_rules.py), so the
    subprocess cost stays negligible; results are cached per path.
    """

    if platform.system() != "Windows":
        return None

    if not path or not os.path.isfile(path):
        return None

    # Single-quote escaping for the PowerShell literal path.
    safe_path = path.replace("'", "''")

    try:

        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}')"
                ".Status.ToString()",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

    except (subprocess.SubprocessError, OSError):
        return None

    status = (completed.stdout or "").strip()

    if not status:
        return None

    return status == "Valid"
