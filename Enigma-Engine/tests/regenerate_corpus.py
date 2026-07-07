#!/usr/bin/env python3
"""Regenerate all corpus reference outputs.
Run from the project root:  python tests/regenerate_corpus.py
"""
import os
import sys
import subprocess

ENGINE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def find_exe():
    for d in ("build", "build-cmake"):
        p = os.path.join(ENGINE_ROOT, d, "enigma_decompile_full.exe")
        if os.path.exists(p):
            return p
    print("Error: enigma_decompile_full.exe not found"); sys.exit(1)

EXE_PATH = find_exe()
EXPECTED = os.path.join(ENGINE_ROOT, "tests", "corpus", "expected")
SLEIGH_DIR = os.path.join(ENGINE_ROOT, "sleigh")
os.environ["ENIGMA_SLEIGH_DIR"] = SLEIGH_DIR
os.makedirs(EXPECTED, exist_ok=True)

def regen(name, args, timeout=30):
    expected_path = os.path.join(EXPECTED, f"{name}.c")
    cmd = [EXE_PATH] + args
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if res.returncode != 0:
        print(f"  [SKIP] {name}: exit code {res.returncode}"); return
    with open(expected_path, "w") as f:
        f.write(res.stdout)
    print(f"  {name}: {len(res.stdout)} bytes")

def bin_path(name):
    return os.path.join(ENGINE_ROOT, name)

def corpus_bin(name):
    p = os.path.join(ENGINE_ROOT, "tests", "corpus", name)
    return p if os.path.exists(p) else bin_path(name)

regen("simple.bin", ["-base", "1000", "-entry", "1000", bin_path("simple.bin")])
regen("ret.bin", ["-base", "1000", "-entry", "1000", bin_path("ret.bin")])
regen("nopfall.bin", ["-base", "1000", "-entry", "1000", bin_path("nopfall.bin")])
regen("jmptail.bin", ["-base", "1000", "-entry", "1000", bin_path("jmptail.bin")])
regen("zerotail.bin", ["-base", "1000", "-entry", "1000", bin_path("zerotail.bin")])
regen("arith.bin", ["-base", "1000", "-entry", "1000", corpus_bin("arith.bin")])
regen("stackframe.bin", ["-base", "1000", "-entry", "1000", corpus_bin("stackframe.bin")])
regen("float_arith.bin", ["-base", "1000", "-entry", "1000", corpus_bin("float_arith.bin")])
regen("float_cmp.bin", ["-base", "1000", "-entry", "1000", corpus_bin("float_cmp.bin")])
regen("simd_int.bin", ["-base", "1000", "-entry", "1000", corpus_bin("simd_int.bin")])
regen("simd_float.bin", ["-base", "1000", "-entry", "1000", corpus_bin("simd_float.bin")])
regen("crypto.bin", ["-base", "1000", "-entry", "1000", corpus_bin("crypto.bin")])
regen("avx.bin", ["-base", "1000", "-entry", "1000", corpus_bin("avx.bin")])
regen("branch_test.bin", ["-base", "1000", "-entry", "1000", corpus_bin("branch_test.bin")])
regen("call_test.bin", ["-base", "1000", "-entry", "1000", corpus_bin("call_test.bin")])

ldr_exe = os.path.join(ENGINE_ROOT, "build-cmake", "enigma_test_loader.exe")
if os.path.exists(ldr_exe):
    regen("pe_test.bin", ["-max-func", "5", ldr_exe], timeout=120)
else:
    print("  [SKIP] pe_test.bin: enigma_test_loader.exe not found")

print("Done. Expected outputs regenerated.")
