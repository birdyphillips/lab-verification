#!/usr/bin/env python3
"""
Config Comparison Script
Compares latest current_<alias>_*.txt in configs/ against latest baseline_<alias>_*.txt in Baseline_Config/
"""

import difflib
import os
import sys
import argparse
from datetime import datetime

SCRIPT_DIR   = os.path.dirname(__file__)
BASELINE_DIR = os.path.join(SCRIPT_DIR, "Baseline_Config")
CURRENT_DIR  = os.path.join(SCRIPT_DIR, "configs")
DIFF_DIR     = os.path.join(SCRIPT_DIR, "diffs")

ALIASES = ["apa", "apc", "ara", "asa", "cts", "dtr"]

# Lines to skip when comparing (pull metadata headers)
SKIP_PREFIXES = ("! Pulled from", "! Pull date", "! Device date", "! ===",
                 "! Running config pulled")


def latest_file(directory: str, prefix: str) -> str | None:
    matches = [f for f in os.listdir(directory) if f.startswith(prefix) and f.endswith(".txt")]
    return os.path.join(directory, sorted(matches)[-1]) if matches else None


def strip_headers(lines: list[str]) -> list[str]:
    return [l for l in lines if not any(l.startswith(p) for p in SKIP_PREFIXES)]


def compare(alias: str, html: bool = False) -> bool:
    baseline_path = latest_file(BASELINE_DIR, f"baseline_{alias}_")
    current_path  = latest_file(CURRENT_DIR,  f"current_{alias}_")

    if not baseline_path:
        print(f"  [SKIP]  {alias} — no baseline found in {BASELINE_DIR}")
        return True
    if not current_path:
        print(f"  [SKIP]  {alias} — no current config found in {CURRENT_DIR}")
        return True

    with open(baseline_path, encoding="utf-8") as f:
        baseline_lines = f.readlines()
    with open(current_path, encoding="utf-8") as f:
        current_lines = f.readlines()

    baseline_clean = strip_headers(baseline_lines)
    current_clean  = strip_headers(current_lines)

    diff = list(difflib.unified_diff(
        baseline_clean, current_clean,
        fromfile=f"BASELINE  {os.path.basename(baseline_path)}",
        tofile=f"CURRENT   {os.path.basename(current_path)}",
        lineterm=""
    ))

    if not diff:
        print(f"  [MATCH]  {alias} — no differences")
        return True

    print(f"  [DIFF]   {alias} — {len(diff)} changed lines")

    os.makedirs(DIFF_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if html:
        html_diff = difflib.HtmlDiff().make_file(
            baseline_clean, current_clean,
            fromdesc=f"BASELINE  {os.path.basename(baseline_path)}",
            todesc=f"CURRENT   {os.path.basename(current_path)}",
            context=True, numlines=3
        )
        out_path = os.path.join(DIFF_DIR, f"diff_{alias}_{timestamp}.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_diff)
    else:
        out_path = os.path.join(DIFF_DIR, f"diff_{alias}_{timestamp}.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(diff))

    print(f"           saved -> {out_path}")
    return False


def run_verification(device: str = None, debug: bool = False):
    """Run Lab_verification_and_trouble_shooting.py to pull fresh configs before comparing."""
    verify_script = os.path.join(SCRIPT_DIR, "Lab_verification_and_trouble_shooting.py")
    if not os.path.exists(verify_script):
        print(f"  [ERROR] Verification script not found: {verify_script}")
        sys.exit(1)

    cmd = [sys.executable, verify_script]
    if device:
        cmd += ["--device", device]
    if debug:
        cmd.append("--debug")

    print(f"\nRunning verification script...")
    import subprocess
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("  [WARN] Verification script exited with errors — continuing with comparison")


def main():
    parser = argparse.ArgumentParser(description="Compare current configs against baselines")
    parser.add_argument("--device",   default=None,  help=f"Alias to compare ({', '.join(ALIASES)})")
    parser.add_argument("--html",     action="store_true", help="Save diff as HTML (side-by-side)")
    parser.add_argument("--no-pull",  action="store_true", help="Skip pulling fresh configs, compare existing")
    parser.add_argument("--debug",    action="store_true", help="Pass --debug to verification script")
    args = parser.parse_args()

    if not args.no_pull:
        run_verification(device=args.device, debug=args.debug)

    targets = [args.device] if args.device else ALIASES
    print(f"\nConfig Comparison  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Baseline : {BASELINE_DIR}")
    print(f"  Current  : {CURRENT_DIR}")
    print(f"  Diffs    : {DIFF_DIR}\n")

    all_match = all(compare(alias, html=args.html) for alias in targets)
    print("\n  All configs match baseline." if all_match
          else "\n  WARNING: Differences detected — review diffs above.")


if __name__ == "__main__":
    main()
