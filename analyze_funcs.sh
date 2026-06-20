#!/bin/bash
export PATH='/mingw64/bin:/usr/bin:$PATH'
export MSYSTEM=MINGW64
bin='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/test_binaries/notepad_test.exe'
tool='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/build-cmake/enigma_pipeline_audit.exe'

# Get func_start addresses
"$tool" "$bin" 2>&1 | grep "func_start_" | sed 's/.*0x//;s/ .*//' | sort -u > /tmp/func_starts.txt
count=$(wc -l < /tmp/func_starts.txt)
echo "Total func_start functions: $count"
echo ""

# For each address, disassemble first 10 instructions and check for ret
while IFS= read -r addr; do
  start_addr=$((16#$addr))
  end_addr=$((start_addr + 32))
  # Get first instruction line
  first_line=$(objdump -d --start-address=0x$addr --stop-address=0x$(printf '%x' $end_addr) "$bin" 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | head -1)
  # Check for ret in first 32 bytes
  has_ret=$(objdump -d --start-address=0x$addr --stop-address=0x$(printf '%x' $end_addr) "$bin" 2>/dev/null | grep -E 'ret|retn|retq' | head -1)
  # Count instructions
  instr_count=$(objdump -d --start-address=0x$addr --stop-address=0x$(printf '%x' $((start_addr + 64))) "$bin" 2>/dev/null | grep -c -E '^\s+[0-9a-f]+:')
  # Get bytes at address
  bytes_at=$(objdump -d --start-address=0x$addr --stop-address=0x$(printf '%x' $((start_addr + 8))) "$bin" 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | head -1 | sed 's/.*:\s*//')
  
  ret_flag="N"
  if [ -n "$has_ret" ]; then
    ret_flag="Y"
  fi
  
  echo "$addr | $ret_flag | $instr_count | $first_line"
done < /tmp/func_starts.txt
