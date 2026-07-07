"""Deterministic output regression test.
Runs the same binary through the decompiler N times and verifies
every run produces byte-identical output. No retries, no probabilistic
workarounds, no normalized comparison. Fail immediately on any divergence."""

import os
import sys
import subprocess
import tempfile

ENGINE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def find_exe():
    for d in ("build", "build-cmake"):
        p = os.path.join(ENGINE_ROOT, d, "enigma_decompile_full.exe")
        if os.path.exists(p):
            return p
    print("Error: enigma_decompile_full.exe not found")
    sys.exit(1)

EXE_PATH = find_exe()
CORPUS = os.path.join(ENGINE_ROOT, "tests", "corpus")
SLEIGH_DIR = os.path.join(ENGINE_ROOT, "sleigh")
os.environ["ENIGMA_SLEIGH_DIR"] = SLEIGH_DIR

NUM_RUNS = 10
tests_passed = 0
tests_failed = 0

def run_decompile(args, timeout=30):
    cmd = [EXE_PATH] + args
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except Exception as e:
        return None, str(e)
    if res.returncode != 0:
        return None, f"exit code {res.returncode}"
    return res.stdout, None

def test_deterministic(name, args, timeout=30):
    global tests_passed, tests_failed
    print(f"  Testing {name} ({NUM_RUNS} runs)...", end=" ")
    # Run 1: capture reference
    ref, err = run_decompile(args, timeout=timeout)
    if err:
        print(f"[FAIL] Run 1 failed: {err}")
        tests_failed += 1
        return
    if not ref or len(ref.splitlines()) < 3:
        print(f"[FAIL] Run 1 produced no output")
        tests_failed += 1
        return
    ref_len = len(ref)
    ref_lines = len(ref.splitlines())
    # Runs 2..N: compare byte-for-byte
    for run in range(2, NUM_RUNS + 1):
        out, err = run_decompile(args, timeout=timeout)
        if err:
            print(f"\n[FAIL] Run {run} failed: {err}")
            tests_failed += 1
            return
        if out != ref:
            print(f"\n[FAIL] Run {run} differs from run 1!")
            # Show first difference
            ref_lines_list = ref.splitlines()
            out_lines_list = out.splitlines()
            for i, (rl, ol) in enumerate(zip(ref_lines_list, out_lines_list)):
                if rl != ol:
                    print(f"  Line {i+1}:")
                    print(f"    run1: {rl[:120]}")
                    print(f"    run{run}: {ol[:120]}")
                    break
            if len(ref_lines_list) != len(out_lines_list):
                print(f"  (line count: run1={len(ref_lines_list)}, run{run}={len(out_lines_list)})")
            tests_failed += 1
            return
    print(f"[PASS] ({ref_len}b, {ref_lines} lines, {NUM_RUNS}/{NUM_RUNS} identical)")
    tests_passed += 1

def bin_path(name):
    return os.path.join(ENGINE_ROOT, name)

def corpus_bin(name):
    return os.path.join(CORPUS, name) if os.path.exists(os.path.join(CORPUS, name)) else bin_path(name)

# === Raw binary tests ===
raw_tests = [
    ("simple.bin", ["-base", "1000", "-entry", "1000", bin_path("simple.bin")]),
    ("ret.bin", ["-base", "1000", "-entry", "1000", bin_path("ret.bin")]),
    ("nopfall.bin", ["-base", "1000", "-entry", "1000", bin_path("nopfall.bin")]),
    ("jmptail.bin", ["-base", "1000", "-entry", "1000", bin_path("jmptail.bin")]),
    ("zerotail.bin", ["-base", "1000", "-entry", "1000", bin_path("zerotail.bin")]),
    ("arith.bin", ["-base", "1000", "-entry", "1000", corpus_bin("arith.bin")]),
    ("stackframe.bin", ["-base", "1000", "-entry", "1000", corpus_bin("stackframe.bin")]),
    ("float_arith.bin", ["-base", "1000", "-entry", "1000", corpus_bin("float_arith.bin")]),
    ("float_cmp.bin", ["-base", "1000", "-entry", "1000", corpus_bin("float_cmp.bin")]),
    ("simd_int.bin", ["-base", "1000", "-entry", "1000", corpus_bin("simd_int.bin")]),
    ("simd_float.bin", ["-base", "1000", "-entry", "1000", corpus_bin("simd_float.bin")]),
    ("crypto.bin", ["-base", "1000", "-entry", "1000", corpus_bin("crypto.bin")]),
    ("avx.bin", ["-base", "1000", "-entry", "1000", corpus_bin("avx.bin")]),
]

for name, args in raw_tests:
    test_deterministic(name, args)

# === PE binary test (single run only; full 10-run determinism is too expensive) ===
ldr_exe = os.path.join(ENGINE_ROOT, "build-cmake", "enigma_test_loader.exe")
if os.path.exists(ldr_exe):
    print(f"  Testing pe_test.bin (1 run)...", end=" ")
    ref, err = run_decompile(["-max-func", "5", ldr_exe], timeout=120)
    if err:
        print(f"[FAIL] {err}")
        tests_failed += 1
    elif not ref or len(ref.splitlines()) < 3:
        print(f"[FAIL] no output")
        tests_failed += 1
    else:
        print(f"[PASS] ({len(ref)}b, {len(ref.splitlines())} lines)")
        tests_passed += 1

print(f"\nDeterminism Test Summary: {tests_passed} passed, {tests_failed} failed")
if tests_failed > 0:
    sys.exit(1)
