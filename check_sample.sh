#!/bin/bash
export PATH='/mingw64/bin:/usr/bin:$PATH'
export MSYSTEM=MINGW64
bin='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/test_binaries/notepad_test.exe'

# Spot-check a few representative func_start addresses
# Function at 0x14000194a (push rbx prologue)
echo "=== 0x14000194a (push rbx) ==="
objdump -d --start-address=0x14000194a --stop-address=0x1400019c4 "$bin" 2>/dev/null | head -30

echo ""
echo "=== 0x140005511 (push rbp) ==="
objdump -d --start-address=0x140005511 --stop-address=0x140005580 "$bin" 2>/dev/null | head -30

echo ""
echo "=== 0x1400064c1 (push rbx) ==="
objdump -d --start-address=0x1400064c1 --stop-address=0x140006550 "$bin" 2>/dev/null | head -30

echo ""
echo "=== 0x14000d168 ==="
objdump -d --start-address=0x14000d168 --stop-address=0x14000d230 "$bin" 2>/dev/null | head -30

echo ""
echo "=== 0x14001c754 ==="
objdump -d --start-address=0x14001c754 --stop-address=0x14001c800 "$bin" 2>/dev/null | head -30
