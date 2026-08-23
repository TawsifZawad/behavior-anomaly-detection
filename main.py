"""
Backwards-compatible entry point.

The project is now driven by the `bads` CLI (see bads.py). Running
`python main.py` is kept working and maps to the full sample demo:

    python bads.py demo

Use `python bads.py --help` to see all commands (learn / detect /
replay / evaluate / benchmark / dashboard / demo).
"""

from bads import main

if __name__ == "__main__":
    # Equivalent to `python bads.py demo`.
    main(["demo"])
