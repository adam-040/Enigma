import os
import sys
import subprocess

ENGINE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def find_exe():
    for d in ("build", "build-cmake"):
        p = os.path.join(ENGINE_ROOT, d, "enigma_decompile_full.exe")
        if os.path.exists(p):
            return p
    print("Error: enigma_decompile_full.exe not found in build/ or build-cmake/")
    sys.exit(1)

EXE_PATH = find_exe()
CORPUS = os.path.join(ENGINE_ROOT, "tests", "corpus")
EXPECTED = os.path.join(CORPUS, "expected")
SLEIGH_DIR = os.path.join(ENGINE_ROOT, "sleigh")

os.environ["ENIGMA_SLEIGH_DIR"] = SLEIGH_DIR

tests_passed = 0
tests_failed = 0

def run_corpus_test(name, args, expected_path, timeout=30):
    global tests_passed, tests_failed
    cmd = [EXE_PATH] + args
    with open(expected_path) as f:
        expected = f.read()
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, timeout=timeout)
        if res.returncode != 0:
            print(f"  [FAIL] {name}: exit code {res.returncode}")
            print(f"    stderr: {res.stderr[:300]}")
            tests_failed += 1
            return
        if res.stdout == expected:
            print(f"  [PASS] {name}")
            tests_passed += 1
            return
        actual_lines = res.stdout.splitlines()
        expected_lines = expected.splitlines()
        for i, (a, e) in enumerate(zip(actual_lines, expected_lines)):
            if a != e:
                print(f"  [FAIL] {name}: Line {i+1} differs:")
                print(f"    - expected: {repr(e[:120])}")
                print(f"    + actual:   {repr(a[:120])}")
                break
        if len(actual_lines) != len(expected_lines):
            print(f"    (line count: actual={len(actual_lines)}, expected={len(expected_lines)})")
        tests_failed += 1
    except subprocess.TimeoutExpired:
        print(f"  [FAIL] {name}: timed out")
        tests_failed += 1
    except FileNotFoundError:
        print(f"  [FAIL] {name}: expected file not found: {expected_path}")
        tests_failed += 1
    except Exception as e:
        print(f"  [FAIL] {name}: {e}")
        tests_failed += 1

def bin_path(name):
    return os.path.join(ENGINE_ROOT, name)

def corpus_bin(name):
    return os.path.join(CORPUS, name) if os.path.exists(os.path.join(CORPUS, name)) else bin_path(name)

# === Raw binary corpus tests (exact bit-identical output comparison) ===
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
    ("branch_test.bin", ["-base", "1000", "-entry", "1000", corpus_bin("branch_test.bin")]),
    ("call_test.bin", ["-base", "1000", "-entry", "1000", corpus_bin("call_test.bin")]),
]

for name, args in raw_tests:
    expected = os.path.join(EXPECTED, f"{name}.c")
    run_corpus_test(name, args, expected)

# === PE binary corpus test ===
ldr_exe = os.path.join(ENGINE_ROOT, "build-cmake", "enigma_test_loader.exe")
if os.path.exists(ldr_exe):
    expected = os.path.join(EXPECTED, "pe_test.bin.c")
    run_corpus_test("pe_test.bin", ["-max-func", "5", ldr_exe], expected, timeout=120)
else:
    print("  [SKIP] pe_test.bin: enigma_test_loader.exe not found")

# === Regeneration helper ===
print("\nTo regenerate expected outputs, run this from the project root:")
print("  python tests/regenerate_corpus.py")

print(f"\nCorpus Regression Summary: {tests_passed} passed, {tests_failed} failed")
if tests_failed > 0:
    sys.exit(1)
