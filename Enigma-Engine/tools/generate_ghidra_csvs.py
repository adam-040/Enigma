#!/usr/bin/env python3
r"""
generate_ghidra_csvs.py

One-time preprocessing script: runs Ghidra headless on a set of PE binaries
and dumps their function addresses+names as CSV golden references.

Usage:
    python generate_ghidra_csvs.py [--binaries BIN1 BIN2 ...]
                                  [--ghidra-home GHIDRA_HOME]
                                  [--output-dir DIR]
                                  [--project-dir DIR]

Default binaries: notepad_test.exe + shell32_test.dll + large/*.dll
Default Ghidra home: C:\Users\pc\Desktop\Crack tools\Ghidra
Output: <output-dir>/ghidra_<basename>.csv
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from pathlib import Path

GHIDRA_HOME = Path("C:/Users/pc/Desktop/Crack tools/Ghidra")
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
TEST_BINARIES = PROJECT_ROOT / "test_binaries"
DEFAULT_OUTPUT = TEST_BINARIES
DEFAULT_PROJECT = PROJECT_ROOT / "ghidra_proj_stress"
GHIDRA_SCRIPT = SCRIPT_DIR / "ghidra_dump_functions.java"

# Binaries to process (name -> path)
DEFAULT_BINARIES = {
    "notepad_test.exe": TEST_BINARIES / "notepad_test.exe",
    "shell32_test.dll": TEST_BINARIES / "shell32_test.dll",
    "kernel32.dll": TEST_BINARIES / "large" / "kernel32.dll",
    "ntdll.dll": TEST_BINARIES / "large" / "ntdll.dll",
    "user32.dll": TEST_BINARIES / "large" / "user32.dll",
}


def run_ghidra_headless(bin_path, basename, ghidra_home, project_dir, output_dir):
    """Run analyzeHeadless on a single binary, save CSV to output_dir."""
    stem = Path(basename).stem
    out_csv = output_dir / f"ghidra_{stem}.csv"
    # Also check older naming convention: ghidra_<basename_without_test_suffix>.csv
    old_csv = output_dir / f"ghidra_{stem.replace('_test', '')}.csv"
    if out_csv.exists() and out_csv.stat().st_size > 100:
        print(f"  [SKIP] {out_csv.name} already exists ({out_csv.stat().st_size} bytes)")
        return True
    if old_csv.exists() and old_csv.stat().st_size > 100:
        print(f"  [SKIP] {old_csv.name} already exists ({old_csv.stat().st_size} bytes)")
        return True

    headless = Path(ghidra_home) / "support" / "analyzeHeadless.bat"
    if not headless.exists():
        print(f"  [ERR] analyzeHeadless.bat not found at {headless}")
        return False

    project_dir = Path(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    # Unique project name per binary to avoid conflicts
    proj_name = f"Stress_{basename.replace('.','_')}"

    GHIDRA_OUTPUT_FILE = SCRIPT_DIR / "ghidra_script_output.tmp"
    if GHIDRA_OUTPUT_FILE.exists():
        GHIDRA_OUTPUT_FILE.unlink()

    print(f"  Importing {bin_path}...")
    t0 = time.time()

    cmd = [
        str(headless),
        str(project_dir),
        proj_name,
        "-import", str(bin_path),
        "-postScript", str(GHIDRA_SCRIPT),
        "-scriptPath", str(GHIDRA_SCRIPT.parent),
        "-deleteProject",
        "-overwrite",
    ]

    # Set env var so the Java script knows where to write
    env = os.environ.copy()
    env["GHIDRA_SCRIPT_OUTPUT"] = str(GHIDRA_OUTPUT_FILE)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour per binary
            env=env,
        )
        elapsed = time.time() - t0

        # Read output from the well-known file written by ghidra_dump_functions.java
        if GHIDRA_OUTPUT_FILE.exists():
            all_out = GHIDRA_OUTPUT_FILE.read_text(encoding="utf-8", errors="replace")
            GHIDRA_OUTPUT_FILE.unlink()
        else:
            all_out = ""
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] Ghidra exceeded 1 hour on {basename}")
        return False
    except FileNotFoundError:
        print(f"  [ERR] Could not run analyzeHeadless.bat \u2014 check Ghidra installation")
        return False

    # Parse output: extract lines matching "0x[0-9a-f]+,<name>"
    csv_lines = []
    for line in all_out.splitlines():
        line = line.strip()
        if line and line.startswith("0x") and "," in line:
            parts = line.split(",", 1)
            try:
                int(parts[0], 16)
                csv_lines.append(line)
            except ValueError:
                pass

    if not csv_lines:
        print(f"  [WARN] No CSV lines found in output after {elapsed:.0f}s")
        print(f"  Ghidra stdout tail:\n{proc.stdout[-500:]}" if proc.stdout else "")
        print(f"  Ghidra stderr tail:\n{proc.stderr[-500:]}" if proc.stderr else "")
        return False

    # Write CSV
    with open(out_csv, "w") as f:
        f.write("address,name\n")
        for line in csv_lines:
            f.write(line + "\n")

    print(f"  [OK] {len(csv_lines)} functions dumped to {out_csv.name} ({elapsed:.0f}s)")
    return True


def main():
    parser = argparse.ArgumentParser(description="Generate Ghidra CSV golden references")
    parser.add_argument("--ghidra-home", default=GHIDRA_HOME, help="Ghidra installation directory")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT, type=Path, help="Output CSV directory")
    parser.add_argument("--project-dir", default=DEFAULT_PROJECT, type=Path, help="Ghidra project directory")
    args = parser.parse_args()

    binaries = DEFAULT_BINARIES

    print("=" * 60)
    print("  GHIDRA CSV GENERATOR")
    print("=" * 60)
    print(f"  Ghidra home: {args.ghidra_home}")
    print(f"  Output dir:  {args.output_dir}")
    print(f"  Project dir: {args.project_dir}")
    print(f"  Script:      {GHIDRA_SCRIPT}")
    print(f"  Binaries:    {len(binaries)}")
    print()

    results = {}
    for basename, bin_path in binaries.items():
        if not bin_path.exists():
            print(f"  [SKIP] {basename} not found at {bin_path}")
            results[basename] = False
            continue

        print(f"\n--- Processing {basename} ({bin_path.stat().st_size / 1024:.0f} KB) ---")
        ok = run_ghidra_headless(
            bin_path, basename,
            args.ghidra_home, args.project_dir, args.output_dir,
        )
        results[basename] = ok

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    success = sum(1 for v in results.values() if v)
    fail = sum(1 for v in results.values() if not v)
    print(f"  Success: {success}, Failed: {fail}")
    for name, ok in results.items():
        stem = Path(name).stem
        status = "OK" if ok else "FAIL"
        csv_path = Path(args.output_dir) / f"ghidra_{stem}"
        size = csv_path.stat().st_size if csv_path.exists() else 0
        print(f"    {status}: {name} -> ghidra_{stem} ({size} bytes)")

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
