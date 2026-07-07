import os
import sys
import subprocess
import re
ENGINE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def find_exe():
    for d in ("build", "build-cmake"):
        p = os.path.join(ENGINE_ROOT, d, "enigma_decompile_full.exe")
        if os.path.exists(p):
            return p
    print("Error: enigma_decompile_full.exe not found in build/ or build-cmake/")
    sys.exit(1)

EXE_PATH = find_exe()
print(f"Using: {EXE_PATH}")

tests_passed = 0
tests_failed = 0

def run_test(name, args, expected_code=0, expect_in_stdout=None,
             expect_not_in_stdout=None, expect_in_stderr=None,
             timeout=30):
    global tests_passed, tests_failed
    cmd = [EXE_PATH] + args
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, timeout=timeout)
        if res.returncode != expected_code:
            print(f"  [FAIL] {name}: expected exit {expected_code}, got {res.returncode}")
            print(f"  stderr: {res.stderr[:500]}")
            tests_failed += 1
            return False
        if expect_in_stdout:
            for pat in expect_in_stdout:
                if not re.search(pat, res.stdout):
                    print(f"  [FAIL] {name}: pattern '{pat}' not in stdout")
                    print(f"  stdout:\n{res.stdout[:800]}")
                    tests_failed += 1
                    return False
        if expect_not_in_stdout:
            for pat in expect_not_in_stdout:
                if re.search(pat, res.stdout):
                    print(f"  [FAIL] {name}: unwanted pattern '{pat}' in stdout")
                    print(f"  stdout:\n{res.stdout[:800]}")
                    tests_failed += 1
                    return False
        if expect_in_stderr:
            for pat in expect_in_stderr:
                if not re.search(pat, res.stderr):
                    print(f"  [FAIL] {name}: pattern '{pat}' not in stderr")
                    tests_failed += 1
                    return False
        print(f"  [PASS] {name}")
        tests_passed += 1
        return True
    except subprocess.TimeoutExpired:
        print(f"  [FAIL] {name}: timed out"); tests_failed += 1; return False
    except Exception as e:
        print(f"  [FAIL] {name}: {e}"); tests_failed += 1; return False

def bin_path(name):
    return os.path.join(ENGINE_ROOT, name)

# === 1. Usage / Help ===
run_test("no-args", [], expected_code=1, expect_in_stderr=["Usage:"])
run_test("help-flag", ["-h"], expected_code=0, expect_in_stderr=["Usage:", "Options:"])

# === 2. Raw binary decompilation — all 5 .bin files ===
run_test("simple.bin", ["-base", "1000", "-entry", "1000", bin_path("simple.bin")],
         expect_in_stdout=[r"FUN_ENTRY", r"uint64_t", r"return\s+0x2a"],
         expect_not_in_stdout=[r"\(void\)", r"xunknown"])
run_test("simple.bin-rebase", ["-base", "2000", "-entry", "2000", bin_path("simple.bin")],
         expect_in_stdout=[r"FUN_ENTRY", r"return\s+0x2a"])
run_test("ret.bin", ["-base", "1000", "-entry", "1000", bin_path("ret.bin")],
         expect_in_stdout=[r"FUN_ENTRY", r"return;"])
run_test("ret.bin-rebase", ["-base", "2000", "-entry", "2000", bin_path("ret.bin")],
         expect_in_stdout=[r"FUN_ENTRY", r"return;"])
run_test("nopfall.bin", ["-base", "1000", "-entry", "1000", bin_path("nopfall.bin")],
         expect_in_stdout=[r"halt_missing"])
run_test("jmptail.bin", ["-base", "1000", "-entry", "1000", bin_path("jmptail.bin")],
         expect_in_stdout=[r"while\( true \)"])
run_test("zerotail.bin", ["-base", "1000", "-entry", "1000", bin_path("zerotail.bin")],
         expect_in_stdout=[r"FUN_ENTRY", r"return;"])

# === 3. CLI flags ===
run_test("max-func-1", ["-base", "1000", "-entry", "1000", "-max-func", "1",
         bin_path("simple.bin")], expect_in_stdout=[r"FUN_ENTRY"])

# Output file
out_dir = os.path.dirname(EXE_PATH)
out_file = os.path.join(out_dir, "cli_test_out.c")
if os.path.exists(out_file):
    try: os.remove(out_file)
    except: pass
run_test("output-file", ["-base", "1000", "-entry", "1000", "-o", out_file,
         bin_path("simple.bin")])
if os.path.exists(out_file):
    with open(out_file) as f:
        c = f.read()
    if "FUN_ENTRY" in c and "0x2a" in c:
        print("  [PASS] output-file: content verified"); tests_passed += 1
    else:
        print("  [FAIL] output-file: bad content"); tests_failed += 1
    try: os.remove(out_file)
    except: pass
else:
    print("  [FAIL] output-file: not created"); tests_failed += 1

# Timing flag
run_test("timing-flag", ["-base", "1000", "-entry", "1000", "-time",
         bin_path("simple.bin")], expect_in_stderr=[r"Timing:", r"total:"],
         expect_in_stdout=[r"return\s+0x2a"])

# === 4. PE auto-detection (on the loader test executable) ===
ldr_exe = os.path.join(ENGINE_ROOT, "build-cmake", "enigma_test_loader.exe")
if os.path.exists(ldr_exe):
    run_test("PE-auto-detect", ["-max-func", "5", ldr_exe],
             expect_in_stdout=[r"entry\(", r"func_(pdata|start|call)_0x", r"return"],
             timeout=120)
    # Symbol resolution: known import names should appear
    run_test("PE-imports", ["-max-func", "3", ldr_exe],
             expect_in_stdout=[r"Sleep\("],
             timeout=120)
    # Empty entry (defaults to base) should still work
    run_test("PE-auto-entry", ["-max-func", "2", ldr_exe],
             expect_in_stdout=[r"entry\(", r"return"],
             timeout=120)
else:
    print("  [SKIP] PE tests: enigma_test_loader.exe not found")

# === 5. Error paths ===
run_test("missing-binary", ["-base", "1000", "-entry", "1000",
         bin_path("nonexistent.bin")], expected_code=1,
         expect_in_stderr=[r"(Error|Exception|not found|failed|No such)"])

run_test("bad-lang", ["-lang", "nonexistent:arch:be:32:default", "-base", "1000",
         bin_path("simple.bin")], expected_code=1,
         expect_in_stderr=[r"(Error|Unable|Unknown language|not found)"])

# Binary smaller than requested address range — tool fills with 0s
run_test("base-beyond-file", ["-base", "FFFFFF00", bin_path("simple.bin")],
         expected_code=0, expect_in_stdout=[r"FUN_ENTRY"])

print(f"\nCLI Regression Summary: {tests_passed} passed, {tests_failed} failed")
if tests_failed > 0:
    sys.exit(1)
