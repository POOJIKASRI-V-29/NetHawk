#!/usr/bin/env python3
"""Diagnose whether LIVE packet capture can work on this machine.

    python3 scripts/check_capture.py

Read-only: it enumerates interfaces and attempts a single short capture probe.
It never transmits anything and never changes any system setting.
"""
from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nethawk.capture.live import (                      # noqa: E402
    capture_available, default_interface, list_interfaces,
    monitor_mode_available, platform_hint,
)

LINE = "-" * 72


def main() -> int:
    print(LINE)
    print("NETHAWK - LIVE CAPTURE DIAGNOSTIC")
    print(LINE)
    print(f"platform        : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"python          : {sys.version.split()[0]}  ({sys.executable})")
    try:
        import scapy
        print(f"scapy           : {scapy.__version__}")
    except Exception as exc:
        print(f"scapy           : NOT AVAILABLE ({exc})")
        print("\nInstall it with:  python3 -m pip install scapy")
        return 1

    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    print(f"effective uid   : {euid} ({'root' if euid == 0 else 'unprivileged'})")

    interfaces = list_interfaces()
    print(f"interfaces ({len(interfaces)}) : {', '.join(interfaces[:12])}"
          + (" ..." if len(interfaces) > 12 else ""))
    print(f"default interface: {default_interface()}")

    if platform.system() == "Darwin":
        print("\nmacOS BPF devices (raw capture is read through these):")
        found = False
        for index in range(4):
            device = Path(f"/dev/bpf{index}")
            if device.exists():
                found = True
                readable = os.access(device, os.R_OK)
                print(f"  {device}  readable by this process: {'YES' if readable else 'NO'}")
        if not found:
            print("  none found")

    print(f"\nmonitor mode    : {'YES' if monitor_mode_available() else 'no'} "
          f"(NetHawk does not require it)")

    print("\nprobing a single packet capture (up to 3 seconds)...")
    status = capture_available(probe_timeout=3.0)
    print(LINE)
    if status.available:
        print("RESULT: LIVE CAPTURE IS AVAILABLE in this process.")
        print("\nStart NetHawk in live mode with:")
        print("    python3 app.py --mode live")
    else:
        print("RESULT: LIVE CAPTURE IS NOT AVAILABLE in this process.")
        print(f"reason: {status.reason}")
        print(f"hint  : {platform_hint()}")
        print("\nTo run NetHawk with live capture, use an elevated interpreter:")
        if platform.system() == "Darwin":
            print(f"    sudo {sys.executable} app.py --mode live")
            print(f"    sudo {sys.executable} scripts/check_capture.py   # verify first")
        elif platform.system() == "Linux":
            print(f"    sudo {sys.executable} app.py --mode live")
            print(f"    # or grant the capability once:")
            print(f"    sudo setcap cap_net_raw,cap_net_admin=eip {sys.executable}")
        else:
            print("    Install Npcap, then run an elevated prompt:")
            print(f"    {sys.executable} app.py --mode live")
        print("\nNo privileges? Both of these exercise the real packet-parsing path:")
        print("    python3 app.py --replay            # replay the bundled capture file")
        print("    python3 app.py                     # DEMO mode dashboard")
    print(LINE)
    return 0 if status.available else 2


if __name__ == "__main__":
    raise SystemExit(main())
