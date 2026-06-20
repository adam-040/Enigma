#!/usr/bin/env python3
"""
stress_test_runner.py

Batch stress-test automation for the Enigma reverse engineering pipeline.
Processes a corpus of PE binaries, records per-analyzer timing + memory,
compares against Ghidra CSV golden references, and generates a consolidated
Markdown report.

Usage:
    python stress_test_runner.py [--binary-dir DIR] [--ghidra-dir DIR]
                                [--timeout SEC] [--output FILE]
                                [--pipeline-audit PATH] [--dump-functions PATH]
                                [--compare-script PATH]
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import time
from collections import OrderedDict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = PROJECT_ROOT / "build-cmake"
TOOLS_DIR = PROJECT_ROOT / "tools"
TEST_BINARIES = PROJECT_ROOT / "test_binaries"

DEFAULT_PIPELINE_AUDIT = BUILD_DIR / "enigma_pipeline_audit.exe"
DEFAULT_DUMP_FUNCTIONS = BUILD_DIR / "enigma_dump_functions.exe"
DEFAULT_COMPARE = TOOLS_DIR / "compare_function_lists.py"

# Table width
SEP = "  " + "-" * 78


def find_pipeline_audit():
    p = DEFAULT_PIPELINE_AUDIT
    return p if p.exists() else None


def find_dump_functions():
    p = DEFAULT_DUMP_FUNCTIONS
    return p if p.exists() else None


def find_compare_script():
    p = DEFAULT_COMPARE
    return p if p.exists() else None


def run_tool(exe, args, timeout, label="tool"):
    """Run an executable with args, return (stdout, stderr, returncode, elapsed)."""
    if not exe:
        return "", f"{label} executable not found", -1, 0.0
    cmd = [str(exe)] + args
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        elapsed = time.time() - t0
        return proc.stdout, proc.stderr, proc.returncode, elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        return "", f"[TIMEOUT after {elapsed:.0f}s]", -1, elapsed
    except FileNotFoundError:
        return "", f"File not found: {exe}", -2, 0.0
    except Exception as e:
        return "", f"Error: {e}", -3, 0.0


def parse_audit_output(stdout):
    """Parse enigma_pipeline_audit stdout into a structured dict."""
    result = {
        "binary_info": {},
        "sections": [],
        "symbols": {},
        "pre_analysis": {},
        "per_analyzer": [],
        "performance": {},
        "coverage": {},
        "function_density": {},
        "stage_timing": [],
        "initial_funcs": 0,
        "final_funcs": 0,
        "initial_instrs": 0,
        "final_instrs": 0,
        "total_time_ms": 0,
        "peak_memory_kb": 0,
    }

    # Binary Info
    m = re.search(r"Format: (.+)", stdout)
    if m:
        result["binary_info"]["format"] = m.group(1).strip()
    m = re.search(r"Arch: (.+)", stdout)
    if m:
        result["binary_info"]["arch"] = m.group(1).strip()
    m = re.search(r"Bitness: (\d+)", stdout)
    if m:
        result["binary_info"]["bitness"] = int(m.group(1))
    m = re.search(r"ImageBase: (0x[0-9a-fA-F]+)", stdout)
    if m:
        result["binary_info"]["image_base"] = m.group(1)
    m = re.search(r"EntryPoint: (0x[0-9a-fA-F]+)", stdout)
    if m:
        result["binary_info"]["entry_point"] = m.group(1)

    # Per-analyzer timing table
    in_table = False
    for line in stdout.splitlines():
        if "PER-ANALYZER TIMING & DELTAS" in line:
            in_table = True
            continue
        if "PERFORMANCE" in line:
            in_table = False
            continue
        if not in_table:
            continue
        # Skip header/separator lines
        if "Analyzer" in line and "Time(ms)" in line:
            continue
        if line.strip().startswith("---"):
            continue
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) >= 5:
            try:
                entry = {
                    "name": parts[0],
                    "time_ms": float(parts[1]),
                    "funcs_delta": parts[2],
                    "instrs_delta": parts[3],
                    "executed": parts[4] == "Y",
                    "exceptions": int(parts[5]) if len(parts) > 5 else 0,
                }
                result["per_analyzer"].append(entry)
            except (ValueError, IndexError):
                pass

    # Performance
    m = re.search(r"Binary load time: ([\d.]+) ms", stdout)
    if m:
        result["performance"]["load_time_ms"] = float(m.group(1))
    m = re.search(r"Analysis time: ([\d.]+) ms", stdout)
    if m:
        result["performance"]["analysis_time_ms"] = float(m.group(1))
    m = re.search(r"Total time: ([\d.]+) ms", stdout)
    if m:
        result["total_time_ms"] = float(m.group(1))
        result["performance"]["total_time_ms"] = float(m.group(1))
    m = re.search(r"Peak memory: ([\d.]+) KB", stdout)
    if m:
        result["peak_memory_kb"] = float(m.group(1))
        result["performance"]["peak_memory_kb"] = float(m.group(1))
    m = re.search(r"Current memory: ([\d.]+) KB", stdout)
    if m:
        result["performance"]["current_memory_kb"] = float(m.group(1))

    # Coverage — find AFTER ANALYSIS section for final counts
    after_analysis = stdout.split("=== AFTER ANALYSIS ===")
    if len(after_analysis) > 1:
        aa_section = after_analysis[1]
        m = re.search(r"Functions:\s*(\d+)", aa_section)
        if m:
            result["coverage"]["functions"] = int(m.group(1))
            result["final_funcs"] = int(m.group(1))
        m = re.search(r"Instructions:\s*(\d+)", aa_section)
        if m:
            result["coverage"]["instructions"] = int(m.group(1))
            result["final_instrs"] = int(m.group(1))

    # Also find executable bytes from COVERAGE section
    m = re.search(r"Executable bytes: (\d+)", stdout)
    if m:
        result["coverage"]["exec_bytes"] = int(m.group(1))
    m = re.search(r"Data items: (\d+)", stdout)
    if m:
        result["coverage"]["data_items"] = int(m.group(1))

    # Initial count from "=== AFTER POPULATEPROGRAM ===" section
    after_pop = stdout.split("=== AFTER POPULATEPROGRAM ===")
    if len(after_pop) > 1:
        ap_section = after_pop[1]
        m = re.search(r"Functions:\s*(\d+)", ap_section)
        if m:
            result["initial_funcs"] = int(m.group(1))
        m = re.search(r"Instructions:\s*(\d+)", ap_section)
        if m:
            result["initial_instrs"] = int(m.group(1))

    # Stage timings
    in_stage = False
    for line in stdout.splitlines():
        if "STAGE TIMING SUMMARY" in line:
            in_stage = True
            continue
        if "FUNCTION DENSITY" in line:
            in_stage = False
            continue
        if not in_stage:
            continue
        if "Stage" in line and "Time(ms)" in line:
            continue
        if line.strip().startswith("---"):
            continue
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) >= 4:
            result["stage_timing"].append({
                "name": parts[0],
                "time_ms": float(parts[1]) if parts[1].replace(".", "").isdigit() else 0,
                "executed": parts[2] == "Y",
                "input": int(parts[3]) if parts[3].isdigit() else 0,
                "output": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
            })

    return result


def parse_dump_functions_csv(stdout):
    """Parse --ghidra-compat CSV output into a dict of address -> name."""
    result = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line == "address,name":
            continue
        parts = line.split(",", 1)
        if len(parts) == 2:
            try:
                addr = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                result[addr] = parts[1].strip()
            except ValueError:
                pass
    return result


def run_comparison(enigma_csv_path, ghidra_csv_path, compare_script):
    """Run compare_function_lists.py and parse its summary output."""
    if not compare_script or not compare_script.exists():
        return None
    cmd = [
        sys.executable, str(compare_script),
        str(enigma_csv_path), str(ghidra_csv_path),
        "--verbose",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = proc.stdout
    except Exception:
        return None

    result = {
        "enigma_total": 0,
        "ghidra_total": 0,
        "matching": 0,
        "extra": 0,
        "missing": 0,
        "extra_list": [],
        "missing_list": [],
        "extra_by_type": {},
    }

    for line in out.splitlines():
        m = re.match(r"Enigma total functions: (\d+)", line)
        if m:
            result["enigma_total"] = int(m.group(1))
        m = re.match(r"Ghidra total functions: (\d+)", line)
        if m:
            result["ghidra_total"] = int(m.group(1))
        m = re.match(r"Matching \(same address\): (\d+)", line)
        if m:
            result["matching"] = int(m.group(1))
        m = re.match(r"Extra \(Enigma only\):\s+(\d+)", line)
        if m:
            result["extra"] = int(m.group(1))
        m = re.match(r"Missing \(Ghidra only\):\s+(\d+)", line)
        if m:
            result["missing"] = int(m.group(1))

    # Parse extra list (handles both with-type and without-type formats)
    in_extra = False
    for line in out.splitlines():
        if "EXTRA FUNCTIONS" in line:
            in_extra = True
            continue
        if "MISSING FUNCTIONS" in line:
            in_extra = False
            continue
        if in_extra and line.strip().startswith("0x"):
            parts = line.strip().split()
            if len(parts) >= 2:
                entry = {"address": parts[0], "name": parts[-1]}
                entry["type"] = parts[1] if len(parts) >= 3 else ""
                result["extra_list"].append(entry)
    in_missing = False
    for line in out.splitlines():
        if "MISSING FUNCTIONS" in line:
            in_missing = True
            continue
        if in_missing and line.strip().startswith("0x"):
            parts = line.strip().split(None, 1)
            if len(parts) >= 2:
                result["missing_list"].append({
                    "address": parts[0],
                    "name": parts[1],
                })

    # Parse extra by type
    for line in out.splitlines():
        m = re.match(r"\s+(\w+): (\d+)", line)
        if m:
            result["extra_by_type"][m.group(1)] = int(m.group(2))

    return result


def format_duration(ms):
    """Format milliseconds to human-readable string."""
    if ms < 1000:
        return f"{ms:.1f} ms"
    s = ms / 1000
    if s < 60:
        return f"{s:.2f} s"
    m = int(s // 60)
    s = s % 60
    return f"{m}m {s:.0f}s"


def generate_report(all_results, output_path):
    """Generate a consolidated Markdown stress test report."""
    lines = []
    lines.append("# Enigma Pipeline Stress Test Report")
    lines.append("")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total binaries | {len(all_results)} |")

    # Aggregate totals
    total_time = sum(r.get("total_time_ms", 0) for r in all_results)
    total_funcs = sum(r.get("final_funcs", 0) for r in all_results)
    peak_memories = [r.get("peak_memory_kb", 0) for r in all_results]
    max_peak_mem = max(peak_memories) if peak_memories else 0
    total_matched = sum(r.get("parity", {}).get("matching", 0) for r in all_results)
    total_ghidra = sum(r.get("parity", {}).get("ghidra_total", 0) for r in all_results)

    lines.append(f"| Total pipeline time | {format_duration(total_time)} |")
    lines.append(f"| Total functions discovered | {total_funcs} |")
    lines.append(f"| Max peak memory | {max_peak_mem:.0f} KB ({max_peak_mem/1024:.1f} MB) |")

    if total_ghidra > 0:
        pct = total_matched / total_ghidra * 100
        lines.append(f"| Ghidra parity (matched) | {total_matched}/{total_ghidra} ({pct:.1f}%) |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Per-binary results
    for i, r in enumerate(all_results):
        name = r.get("name", f"binary_{i}")
        size_mb = r.get("size_mb", 0)
        lines.append(f"## {i+1}. {name}")
        lines.append("")
        lines.append(f"**Size**: {size_mb:.2f} MB  ")
        lines.append(f"**Pipeline time**: {format_duration(r.get('total_time_ms', 0))}  ")
        lines.append(f"**Peak memory**: {r.get('peak_memory_kb', 0):.0f} KB ({r.get('peak_memory_kb', 0)/1024:.1f} MB)  ")
        lines.append("")

        # Binary info
        bi = r.get("binary_info", {})
        if bi:
            lines.append("### Binary Properties")
            lines.append("")
            lines.append(f"| Property | Value |")
            lines.append(f"|----------|-------|")
            for k, v in bi.items():
                lines.append(f"| {k} | {v} |")
            lines.append("")

        # Function/instruction summary
        perf = r.get("performance", {})
        cov = r.get("coverage", {})
        lines.append("### Pipeline Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Load time | {perf.get('load_time_ms', 0):.1f} ms |")
        lines.append(f"| Analysis time | {perf.get('analysis_time_ms', 0):.1f} ms |")
        lines.append(f"| Total pipeline time | {r.get('total_time_ms', 0):.1f} ms |")
        lines.append(f"| Initial functions | {r.get('initial_funcs', 0)} |")
        lines.append(f"| Final functions | {r.get('final_funcs', 0)} |")
        lines.append(f"| Function growth | +{r.get('final_funcs', 0) - r.get('initial_funcs', 0)} |")
        lines.append(f"| Instructions | {cov.get('instructions', 0)} |")
        lines.append(f"| Data items | {cov.get('data_items', 0)} |")
        lines.append(f"| Executable bytes | {cov.get('exec_bytes', 0)} |")
        lines.append(f"| Peak memory | {r.get('peak_memory_kb', 0):.0f} KB |")
        lines.append("")

        # Per-analyzer breakdown
        analyzers = r.get("per_analyzer", [])
        if analyzers:
            lines.append("### Per-Analyzer Timing")
            lines.append("")
            lines.append(f"| Analyzer | Time (ms) | % of pipeline | Funcs Δ | Instrs Δ | Exceptions |")
            lines.append(f"|---------|-----------|---------------|---------|----------|------------|")
            total = r.get("total_time_ms", 1)
            for a in analyzers:
                pct = a["time_ms"] / total * 100 if total > 0 else 0
                lines.append(
                    f"| {a['name']} | {a['time_ms']:.1f} | {pct:.1f}% | "
                    f"{a['funcs_delta']} | {a['instrs_delta']} | {a['exceptions']} |"
                )
            lines.append("")

        # Stage timing
        stages = r.get("stage_timing", [])
        if stages:
            lines.append("### Stage Timing")
            lines.append("")
            lines.append(f"| Stage | Time (ms) | Executed? | Input → Output |")
            lines.append(f"|-------|-----------|-----------|----------------|")
            for s in stages:
                lines.append(
                    f"| {s['name']} | {s['time_ms']:.1f} | {'Y' if s['executed'] else 'N'} | "
                    f"{s['input']} → {s['output']} |"
                )
            lines.append("")

        # Ghidra parity
        parity = r.get("parity", {})
        if parity and parity.get("ghidra_total", 0) > 0:
            lines.append("### Ghidra Parity")
            lines.append("")
            match_pct = parity["matching"] / parity["ghidra_total"] * 100 if parity["ghidra_total"] > 0 else 0
            lines.append(f"| Metric | Count | % |")
            lines.append(f"|--------|-------|---|")
            lines.append(f"| Ghidra total | {parity['ghidra_total']} | 100% |")
            lines.append(f"| Matched | {parity['matching']} | {match_pct:.1f}% |")
            lines.append(f"| Missing | {parity['missing']} | {parity['missing']/parity['ghidra_total']*100:.1f}% |")
            lines.append(f"| Extra (Enigma only) | {parity['extra']} | — |")
            lines.append(f"| Enigma total | {parity['enigma_total']} | — |")
            lines.append("")

            if parity.get("extra_by_type"):
                lines.append("#### Extra Functions by Type")
                lines.append("")
                lines.append(f"| Type | Count |")
                lines.append(f"|------|-------|")
                for t, c in sorted(parity["extra_by_type"].items()):
                    lines.append(f"| {t} | {c} |")
                lines.append("")

            if parity.get("missing_list"):
                lines.append("#### Missing Functions (Ghidra only)")
                lines.append("")
                for mf in parity["missing_list"]:
                    lines.append(f"- `{mf['address']}` {mf['name']}")
                lines.append("")

        lines.append("---")
        lines.append("")

    # Cross-binary bottleneck analysis
    lines.append("## Cross-Binary Bottleneck Analysis")
    lines.append("")

    # Aggregate per-analyzer timing across all binaries
    analyzer_agg = {}
    for r in all_results:
        for a in r.get("per_analyzer", []):
            name = a["name"]
            if name not in analyzer_agg:
                analyzer_agg[name] = {"total_ms": 0, "count": 0, "max_ms": 0}
            analyzer_agg[name]["total_ms"] += a["time_ms"]
            analyzer_agg[name]["count"] += 1
            analyzer_agg[name]["max_ms"] = max(analyzer_agg[name]["max_ms"], a["time_ms"])

    if analyzer_agg:
        total_all = sum(v["total_ms"] for v in analyzer_agg.values())
        lines.append(f"| Analyzer | Total Time (ms) | Avg Time (ms) | Max Time (ms) | % of Pipeline |")
        lines.append(f"|---------|-----------------|---------------|---------------|---------------|")
        for name, v in sorted(analyzer_agg.items(), key=lambda x: -x[1]["total_ms"]):
            avg = v["total_ms"] / v["count"] if v["count"] > 0 else 0
            pct = v["total_ms"] / total_all * 100 if total_all > 0 else 0
            lines.append(
                f"| {name} | {v['total_ms']:.1f} | {avg:.1f} | {v['max_ms']:.1f} | {pct:.1f}% |"
            )
        lines.append("")

    # Memory scaling
    lines.append("## Memory Scaling")
    lines.append("")
    lines.append(f"| Binary | Size (MB) | Peak Memory (MB) | Memory / Size Ratio |")
    lines.append(f"|--------|-----------|-------------------|---------------------|")
    for r in all_results:
        size = r.get("size_mb", 0)
        mem = r.get("peak_memory_kb", 0) / 1024
        ratio = mem / size if size > 0 else 0
        lines.append(
            f"| {r.get('name', '?')} | {size:.2f} | {mem:.1f} | {ratio:.2f}x |"
        )
    lines.append("")

    # Function discovery efficiency
    lines.append("## Function Discovery Efficiency")
    lines.append("")
    lines.append(f"| Binary | Functions | Instructions | Exec Bytes | Instrs/Func | Funcs/MB exec |")
    lines.append(f"|--------|-----------|--------------|------------|-------------|---------------|")
    for r in all_results:
        funcs = r.get("final_funcs", 0)
        instrs = r.get("final_instrs", 0)
        exec_bytes = r.get("coverage", {}).get("exec_bytes", 1)
        instr_per_func = instrs / funcs if funcs > 0 else 0
        funcs_per_mb = funcs / (exec_bytes / 1048576) if exec_bytes > 0 else 0
        lines.append(
            f"| {r.get('name', '?')} | {funcs} | {instrs} | {exec_bytes} | "
            f"{instr_per_func:.1f} | {funcs_per_mb:.0f} |"
        )
    lines.append("")

    # Recommendations
    lines.append("## Observations & Recommendations")
    lines.append("")

    # Find slowest analyzers
    if analyzer_agg:
        sorted_analyzers = sorted(analyzer_agg.items(), key=lambda x: -x[1]["total_ms"])
        top3 = sorted_analyzers[:3]
        lines.append("### Top Time Consumers")
        for name, v in top3:
            avg = v["total_ms"] / v["count"] if v["count"] > 0 else 0
            lines.append(f"- **{name}**: avg {avg:.1f} ms, max {v['max_ms']:.1f} ms across {v['count']} binaries")

    # Memory concerns
    max_mem_bin = max(all_results, key=lambda r: r.get("peak_memory_kb", 0))
    if max_mem_bin.get("peak_memory_kb", 0) > 500 * 1024:  # >500MB
        lines.append(f"")
        lines.append("### Memory Warning")
        lines.append(f"- **{max_mem_bin.get('name', '?')}** peaked at {max_mem_bin['peak_memory_kb']/1024:.0f} MB — investigate potential leak")

    # Missing functions
    total_missing = sum(r.get("parity", {}).get("missing", 0) for r in all_results if r.get("parity"))
    if total_missing > 0:
        lines.append(f"")
        lines.append("### Missing Functions")
        lines.append(f"- {total_missing} functions missing across all binaries with Ghidra CSVs")
        for r in all_results:
            if r.get("parity", {}).get("missing", 0) > 0:
                lines.append(f"  - {r['name']}: {r['parity']['missing']} missing")

    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by stress_test_runner.py at {time.strftime('%Y-%m-%d %H:%M:%S')}*")

    report = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Batch stress-test the Enigma pipeline against PE binaries"
    )
    parser.add_argument("--binary-dir", type=Path, default=TEST_BINARIES,
                        help="Directory containing test binaries (default: test_binaries/)")
    parser.add_argument("--ghidra-dir", type=Path, default=TEST_BINARIES,
                        help="Directory containing ghidra_*.csv files (default: test_binaries/)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Per-binary timeout in seconds (default: 300)")
    parser.add_argument("--output", type=Path, default=Path("stress_test_report.md"),
                        help="Output Markdown report path (default: stress_test_report.md)")
    parser.add_argument("--pipeline-audit", type=Path,
                        default=find_pipeline_audit(),
                        help="Path to enigma_pipeline_audit.exe")
    parser.add_argument("--dump-functions", type=Path,
                        default=find_dump_functions(),
                        help="Path to enigma_dump_functions.exe")
    parser.add_argument("--compare-script", type=Path,
                        default=find_compare_script(),
                        help="Path to compare_function_lists.py")
    parser.add_argument("binaries", nargs="*",
                        help="Specific binaries to test (default: auto-discover from --binary-dir)")
    args = parser.parse_args()

    # Validate executables
    if not args.pipeline_audit or not args.pipeline_audit.exists():
        print(f"[ERR] pipeline_audit not found: {args.pipeline_audit}")
        sys.exit(1)
    if not args.dump_functions or not args.dump_functions.exists():
        print(f"[ERR] dump_functions not found: {args.dump_functions}")
        sys.exit(1)

    # Discover binaries
    if args.binaries:
        binary_paths = [Path(b) for b in args.binaries]
    else:
        # Default corpus: notepad + shell32 + large/*.dll
        binary_paths = [
            args.binary_dir / "notepad_test.exe",
            args.binary_dir / "shell32_test.dll",
            args.binary_dir / "large" / "kernel32.dll",
            args.binary_dir / "large" / "ntdll.dll",
            args.binary_dir / "large" / "user32.dll",
        ]

    # Filter to existing files
    binary_paths = [p for p in binary_paths if p.exists()]
    if not binary_paths:
        print("[ERR] No binaries found to test")
        sys.exit(1)

    print("=" * 60)
    print("  ENIGMA STRESS TEST RUNNER")
    print("=" * 60)
    print(f"  Pipeline audit:  {args.pipeline_audit}")
    print(f"  Dump functions:  {args.dump_functions}")
    print(f"  Compare script:  {args.compare_script}")
    print(f"  Timeout:         {args.timeout}s per binary")
    print(f"  Binaries:        {len(binary_paths)}")
    for p in binary_paths:
        print(f"    {p.name} ({p.stat().st_size / 1024:.0f} KB)")
    print()

    all_results = []

    for bin_path in binary_paths:
        basename = bin_path.name
        size_mb = bin_path.stat().st_size / (1024 * 1024)
        # Ghidra CSV naming convention: ghidra_<stem>.csv
        stem = Path(basename).stem
        ghidra_csv = None
        for candidate in [
            Path(args.ghidra_dir) / f"ghidra_{stem}.csv",
            Path(args.ghidra_dir) / f"ghidra_{stem.replace('_test', '')}.csv",
            Path(args.ghidra_dir) / f"ghidra_{basename}.csv",
        ]:
            if candidate.exists():
                ghidra_csv = candidate
                break

        print(f"\n--- [{basename}] ---")
        print(f"  Size: {size_mb:.2f} MB")

        # Step A: Run pipeline_audit
        print(f"  Running pipeline_audit (timeout={args.timeout}s)...")
        stdout, stderr, rc, elapsed = run_tool(
            args.pipeline_audit, [str(bin_path)], args.timeout, "pipeline_audit"
        )
        if rc != 0:
            print(f"  [FAIL] pipeline_audit exited with code {rc}")
            print(f"  stderr: {stderr[:200]}")
            # Still create a result entry with what we have
            result = {
                "name": basename,
                "size_mb": size_mb,
                "total_time_ms": elapsed * 1000,
                "peak_memory_kb": 0,
                "error": stderr,
            }
            all_results.append(result)
            continue

        result = parse_audit_output(stdout)
        result["name"] = basename
        result["size_mb"] = size_mb
        print(f"  Load: {result['performance'].get('load_time_ms', 0):.0f}ms, "
              f"Analysis: {result['performance'].get('analysis_time_ms', 0):.0f}ms, "
              f"Total: {result['total_time_ms']:.0f}ms, "
              f"Peak mem: {result['peak_memory_kb']:.0f}KB")

        # Step B: Run dump_functions
        print(f"  Running enigma_dump_functions...")
        dump_stdout, dump_stderr, dump_rc, dump_elapsed = run_tool(
            args.dump_functions, [str(bin_path), "--ghidra-compat"], args.timeout, "dump_functions"
        )
        if dump_rc == 0 and dump_stdout:
            enigma_funcs = parse_dump_functions_csv(dump_stdout)
            result["enigma_func_count"] = len(enigma_funcs)
            print(f"  Functions: {len(enigma_funcs)}")
        else:
            result["enigma_func_count"] = 0
            print(f"  [WARN] dump_functions failed: {dump_stderr[:200]}")

        # Step C: Compare against Ghidra CSV (if available)
        if ghidra_csv.exists() and args.compare_script:
            print(f"  Comparing against {ghidra_csv.name}...")
            # Write Enigma CSV to temp for comparison
            tmp_enigma_csv = bin_path.parent / f"_tmp_enigma_{basename}.csv"
            try:
                with open(tmp_enigma_csv, "w") as f:
                    if "enigma_funcs" in result:
                        for addr, name in result["enigma_funcs"].items():
                            f.write(f"0x{addr:x},{name}\n")
                    else:
                        # Write dump output
                        f.write(dump_stdout)

                parity = run_comparison(tmp_enigma_csv, ghidra_csv, args.compare_script)
                if parity:
                    result["parity"] = parity
                    match_pct = parity["matching"] / parity["ghidra_total"] * 100 if parity["ghidra_total"] > 0 else 0
                    print(f"  Matched: {parity['matching']}/{parity['ghidra_total']} ({match_pct:.1f}%), "
                          f"Missing: {parity['missing']}, Extra: {parity['extra']}")
                else:
                    print(f"  [WARN] comparison returned no results")
            finally:
                if tmp_enigma_csv.exists():
                    tmp_enigma_csv.unlink()
        else:
            if not ghidra_csv.exists():
                print(f"  [INFO] No Ghidra CSV at {ghidra_csv}")
            if not args.compare_script:
                print(f"  [INFO] compare script not available")

        # Enrich result with function dict
        if dump_rc == 0 and dump_stdout:
            result["enigma_funcs"] = parse_dump_functions_csv(dump_stdout)
        else:
            result["enigma_funcs"] = {}

        all_results.append(result)
        print(f"  [DONE]")

    # Generate report
    print(f"\n{'=' * 60}")
    print(f"  Generating report: {args.output}")
    report = generate_report(all_results, args.output)
    print(f"  Report written ({len(report)} bytes)")
    print(f"{'=' * 60}")

    # Print summary
    print(f"\nFINAL SUMMARY:")
    for r in all_results:
        name = r.get("name", "?")
        time_ms = r.get("total_time_ms", 0)
        mem_kb = r.get("peak_memory_kb", 0)
        funcs = r.get("final_funcs", r.get("enigma_func_count", 0))
        parity = r.get("parity", {})
        missing = parity.get("missing", "N/A") if parity else "N/A"
        print(f"  {name:30s} {time_ms:8.0f}ms  {mem_kb:8.0f}KB  {funcs:5d} funcs  missing={missing}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
