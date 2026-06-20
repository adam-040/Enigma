#!/bin/bash
export PATH='/mingw64/bin:/usr/bin:$PATH'
export MSYSTEM=MINGW64
bin='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/test_binaries/notepad_test.exe'
for addr in 140001008 140001094 140001130 14000125c 140001300 140001380 140001520 1400016c4 14000175c 1400017e8 1400018c0 140001940 1400019c4 140001c38 140001c58 140001c78 140001ca0 140001cb4 140001ce0 140001e20; do
  echo -n "$addr: "
  objdump -d --start-address=0x$addr --stop-address=$((0x$addr + 12)) "$bin" 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | head -1
done
