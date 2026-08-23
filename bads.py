#!/usr/bin/env python
"""
bads — Behavior Anomaly Detection System

A single command-line entry point for the whole hybrid SIEM + network +
host + anomaly detection pipeline. There is no development/production
mode flag: each subcommand does one clear thing.

    python bads.py learn        establish baselines + train the model
    python bads.py detect       analyse the LIVE session (host+net+SIEM)
    python bads.py replay        analyse a sample session (reproducible)
    python bads.py evaluate     score the model on the held-out eval set
    python bads.py benchmark    run the NSL-KDD benchmark
    python bads.py dashboard    (re)build the HTML dashboard
    python bads.py demo         full end-to-end demo, then open dashboard

Typical first run:      python bads.py demo
Real deployment:        python bads.py learn   (once, on normal activity)
                        python bads.py detect  (each monitoring cycle)
"""

import os
import sys
import argparse
import subprocess


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True  # non-Windows or undetectable


def _relaunch_elevated(extra_args):
    """
    Relaunch this program elevated via the Windows UAC prompt. Returns
    True if the elevated process was launched. The new process re-locates
    the project root from the executable path, so a system32 working
    directory does not matter.
    """
    import ctypes

    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = subprocess.list2cmdline(extra_args)
    else:
        exe = sys.executable
        params = subprocess.list2cmdline(
            [os.path.abspath(__file__)] + extra_args
        )

    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, os.getcwd(), 1
        )
        return int(rc) > 32
    except Exception:
        return False


def _locate_project_root():
    """
    Find the project directory (the one holding demo/ and config/) by
    walking up from the executable / script location. Lets the app be run
    from anywhere — double-clicked, from dist/, or from the repo root —
    because all data, model and report paths are resolved against it.
    """
    if getattr(sys, "frozen", False):          # PyInstaller build
        start = os.path.dirname(sys.executable)
    else:
        start = os.path.dirname(os.path.abspath(__file__))

    current = start
    for _ in range(8):
        if (os.path.isdir(os.path.join(current, "demo"))
                and os.path.isdir(os.path.join(current, "config"))):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


# Anchor the working directory to the project root BEFORE importing the
# pipeline (importing core.logger creates logs/ in the cwd, so the chdir
# must happen first).
_root = _locate_project_root()
if _root:
    os.chdir(_root)


from core import pipeline  # noqa: E402
from config.settings import (  # noqa: E402
    BASELINE_EVENT_FILE,
    CURRENT_EVENT_FILE,
    SURICATA_EVE_FILE,
    WAZUH_ALERTS_FILE,
)

MODEL_PATH = "ml/model.joblib"


def _require_model():
    if not os.path.exists(MODEL_PATH):
        print(
            "No trained model found. Run `python bads.py learn` first "
            "(or `python bads.py demo` for the full sample run)."
        )
        return False
    return True


# ---------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------

def cmd_learn(args):
    pipeline.learn_baseline(args.baseline)
    print("\nLearning complete. Model and baselines are ready.")


def cmd_detect(args):
    if not _require_model():
        return
    vectors = pipeline.collect_live(username=args.user)
    pipeline.analyze(vectors, is_live=True)


def cmd_own(args):
    """OWN: collect from THIS computer now and report on it."""
    import platform as _pf

    # Reading the Windows Security log needs Administrator rights. When
    # not elevated, request UAC elevation and run the real scan in the
    # new admin window.
    if (_pf.system() == "Windows"
            and not getattr(args, "elevated", False)
            and not _is_admin()):
        print("\nOwn mode needs Administrator to read the Windows "
              "Security log.")
        print("Requesting elevation — please accept the UAC prompt...")
        if _relaunch_elevated(["own", "--elevated"]):
            print("An Administrator window is now running the scan. "
                  "You can close this window.")
            return
        print("Elevation was declined — continuing with limited host "
              "access.\n")

    pipeline.ensure_model()

    print("\n" + "=" * 52)
    print(" OWN  —  scanning THIS computer")
    print("=" * 52)

    # Host plus any configured LIVE Suricata / Wazuh feeds (settings
    # LIVE_SURICATA_EVE_FILE / LIVE_WAZUH_ALERTS_FILE). Blank/absent feeds
    # are skipped, so this stays host-only on machines without them.
    vectors = pipeline.collect_live(username=args.user, include_sensors=True)

    if vectors:
        pipeline.analyze(vectors, is_live=True, model_path=pipeline.OWN_MODEL)
        new_users = pipeline.establish_baselines(vectors)
        # On a machine's first scan, teach the own-model its normal so
        # future benign scans stop reading as anomalies (ML cold-start).
        if new_users:
            first_run = [v for v in vectors if v.username in new_users]
            pipeline.learn_own_normal(first_run)
        pipeline.build_dashboard(open_browser=not args.no_open)
    else:
        print("No activity could be collected from this machine.")

    # The elevated relaunch runs with an argument, so main()'s
    # double-click pause does not apply — keep this window open here.
    if getattr(args, "elevated", False):
        try:
            input("\nPress Enter to close...")
        except EOFError:
            pass


def cmd_watch(args):
    """WATCH: run Own continuously, refreshing the dashboard each cycle."""
    import time
    import platform as _pf

    if (_pf.system() == "Windows"
            and not getattr(args, "elevated", False)
            and not _is_admin()):
        print("\nLive monitoring needs Administrator to read the "
              "Windows Security log.")
        print("Requesting elevation — please accept the UAC prompt...")
        if _relaunch_elevated(
            ["watch", "--interval", str(args.interval), "--elevated"]
        ):
            print("An Administrator window is now monitoring live. "
                  "You can close this window.")
            return
        print("Elevation declined — monitoring with limited host access.\n")

    pipeline.ensure_model()

    print("\n" + "=" * 52)
    print(f" LIVE MONITOR  —  scanning every {args.interval}s")
    print(" Press Ctrl+C to stop.")
    print("=" * 52)

    first = True
    cycle = 0
    try:
        while True:
            cycle += 1
            print(f"\n----- scan #{cycle} -----")

            vectors = pipeline.collect_live(
                username=args.user, include_sensors=True
            )
            if vectors:
                pipeline.analyze(
                    vectors, is_live=True, model_path=pipeline.OWN_MODEL
                )
                new_users = pipeline.establish_baselines(vectors)
                if new_users:
                    pipeline.learn_own_normal(
                        [v for v in vectors if v.username in new_users]
                    )

            pipeline.build_dashboard(
                open_browser=first, auto_refresh=args.interval
            )
            first = False

            print(f"next scan in {args.interval}s ...")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nLive monitoring stopped.")


def cmd_analyze(args):
    """ANALYZE: report on the stored sample data (no live capture)."""
    pipeline.ensure_model()

    print("\n" + "=" * 52)
    print(" ANALYZE  —  stored sample data")
    print("=" * 52)

    vectors = pipeline.load_session_file(
        events_file=CURRENT_EVENT_FILE,
        network_file=SURICATA_EVE_FILE,
        siem_file=WAZUH_ALERTS_FILE,
        attribute_to="Rahim",
    )
    pipeline.analyze(vectors, is_live=False)
    pipeline.build_dashboard(open_browser=not args.no_open)


def cmd_replay(args):
    if not _require_model():
        return
    vectors = pipeline.load_session_file(
        events_file=args.events,
        network_file=args.network,
        siem_file=args.siem,
        attribute_to=args.attribute_to,
    )
    pipeline.analyze(vectors, is_live=False)


def cmd_evaluate(args):
    pipeline.evaluate()


def cmd_benchmark(args):
    from scripts.nsl_kdd_benchmark import main as run_benchmark
    run_benchmark()


def cmd_dashboard(args):
    pipeline.build_dashboard(open_browser=args.open)


def cmd_demo(args):
    print("========== bads demo: full end-to-end run ==========")

    # 1. learn baselines + train the model
    pipeline.learn_baseline(BASELINE_EVENT_FILE)

    # 2. analyse a reproducible multi-stage session that spans all three
    #    planes: host events (file) + Suricata network + Wazuh SIEM, the
    #    network/SIEM telemetry attributed to the attacker user so the
    #    cross-plane and hybrid correlation chains fire.
    print("\n===== Current Session (sample: host + network + SIEM) =====")
    vectors = pipeline.load_session_file(
        events_file=CURRENT_EVENT_FILE,
        network_file=SURICATA_EVE_FILE,
        siem_file=WAZUH_ALERTS_FILE,
        attribute_to="Rahim",
    )
    pipeline.analyze(vectors, is_live=False)

    # 3. evaluate + dashboard
    pipeline.evaluate()
    pipeline.build_dashboard(open_browser=not args.no_open)

    print("\n========== demo complete ==========")


# ---------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="bads",
        description="Behavior Anomaly Detection System",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_learn = sub.add_parser("learn", help="establish baselines + train")
    p_learn.add_argument("--baseline", default=BASELINE_EVENT_FILE,
                         help="normal-behavior events file")
    p_learn.set_defaults(func=cmd_learn)

    p_detect = sub.add_parser("detect", help="analyse the live session")
    p_detect.add_argument("--user", default=None,
                          help="attribute network/SIEM events to this user")
    p_detect.set_defaults(func=cmd_detect)

    p_own = sub.add_parser("own", help="scan THIS computer + dashboard")
    p_own.add_argument("--user", default=None,
                       help="attribute network/SIEM events to this user")
    p_own.add_argument("--no-open", action="store_true")
    # Internal: set on the UAC-elevated relaunch so it keeps its window
    # open. Hidden from --help.
    p_own.add_argument("--elevated", action="store_true",
                       help=argparse.SUPPRESS)
    p_own.set_defaults(func=cmd_own)

    p_analyze = sub.add_parser("analyze",
                               help="analyse stored sample data + dashboard")
    p_analyze.add_argument("--no-open", action="store_true")
    p_analyze.set_defaults(func=cmd_analyze)

    p_watch = sub.add_parser("watch",
                             help="LIVE: scan THIS computer on a loop")
    p_watch.add_argument("--interval", type=int, default=60,
                         help="seconds between scans (default 60)")
    p_watch.add_argument("--user", default=None)
    p_watch.add_argument("--elevated", action="store_true",
                         help=argparse.SUPPRESS)
    p_watch.set_defaults(func=cmd_watch)

    p_replay = sub.add_parser("replay", help="analyse a sample session")
    p_replay.add_argument("--events", default=CURRENT_EVENT_FILE)
    p_replay.add_argument("--network", default=SURICATA_EVE_FILE)
    p_replay.add_argument("--siem", default=WAZUH_ALERTS_FILE)
    p_replay.add_argument("--attribute-to", default="Rahim",
                          help="user to attribute network/SIEM telemetry to")
    p_replay.set_defaults(func=cmd_replay)

    p_eval = sub.add_parser("evaluate", help="score the model on eval set")
    p_eval.set_defaults(func=cmd_evaluate)

    p_bench = sub.add_parser("benchmark", help="run the NSL-KDD benchmark")
    p_bench.set_defaults(func=cmd_benchmark)

    p_dash = sub.add_parser("dashboard", help="(re)build the dashboard")
    p_dash.add_argument("--open", action="store_true",
                        help="open the dashboard in a browser")
    p_dash.set_defaults(func=cmd_dashboard)

    p_demo = sub.add_parser("demo", help="full end-to-end sample run")
    p_demo.add_argument("--no-open", action="store_true",
                        help="do not open the dashboard afterwards")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def _interactive_menu():
    """Shown when the app is launched with no arguments (double-click)."""
    print("=" * 52)
    print(" Behavior Anomaly Detection System  (bads)")
    print("=" * 52)
    print("  [1] Own      - scan THIS computer once  (Run as administrator)")
    print("  [2] Analyze  - report on stored sample data")
    print("  [3] Live     - keep monitoring THIS computer (Run as admin)")
    print("=" * 52)

    try:
        raw = input("Select mode [1/2/3] (default 1): ")
    except EOFError:
        raw = ""

    # Strip a possible BOM / whitespace (some shells prepend one when
    # input is piped) before interpreting the choice.
    choice = raw.replace("﻿", "").strip()

    if choice.startswith("2"):
        return ["analyze"]
    if choice.startswith("3"):
        return ["watch"]
    return ["own"]


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Launched with no arguments (e.g. double-clicked): ask which mode to
    # run and keep the console window open afterwards so output is
    # readable instead of flashing an argparse error and closing.
    double_clicked = getattr(sys, "frozen", False) and len(argv) == 0
    if len(argv) == 0:
        argv = _interactive_menu()

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        args.func(args)
    finally:
        if double_clicked:
            try:
                input("\nPress Enter to close...")
            except EOFError:
                pass


if __name__ == "__main__":
    main()
