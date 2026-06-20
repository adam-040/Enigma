#!/bin/bash
export PATH='/mingw64/bin:/usr/bin:$PATH'
export MSYSTEM=MINGW64
bin='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/test_binaries/notepad_test.exe'

echo "=== SUSPICIOUS FUNCTION 1: 0x1400017e8 ==="
objdump -d --start-address=0x1400017e8 --stop-address=0x140001900 "$bin" 2>/dev/null | head -80

echo ""
echo "=== SUSPICIOUS FUNCTION 2: 0x14001fbe3 ==="
objdump -d --start-address=0x14001fbe3 --stop-address=0x14001fce0 "$bin" 2>/dev/null | head -60

echo ""
echo "=== SUSPICIOUS FUNCTION 3: 0x14001fd47 ==="
objdump -d --start-address=0x14001fd47 --stop-address=0x14001fe00 "$bin" 2>/dev/null | head -60
