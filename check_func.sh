#!/bin/bash
export PATH='/mingw64/bin:/usr/bin:$PATH'
export MSYSTEM=MINGW64
bin='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/test_binaries/notepad_test.exe'
addr=0x1400016c4
end=0x140001718
objdump -d --start-address=$addr --stop-address=$end "$bin" 2>/dev/null
