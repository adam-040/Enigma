#!/bin/bash
export PATH='/mingw64/bin:/usr/bin:$PATH'
export MSYSTEM=MINGW64
bin='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/test_binaries/notepad_test.exe'
tool='/c/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/build-cmake/enigma_pipeline_audit.exe'

# Get func_start addresses sorted
"$tool" "$bin" 2>&1 | grep "func_start_" | sed 's/.*0x//;s/ .*//' | sort -u > /tmp/fs_addrs.txt
total=$(wc -l < /tmp/fs_addrs.txt)

echo "Total func_start candidates: $total"
echo ""

# Batch disassemble - do entire .text once
# Get .text section offset from objdump
text_info=$(objdump -h "$bin" 2>/dev/null | grep '.text')
echo "Text section: $text_info"

confirmed=0
no_ret=0
suspect=0

echo ""
echo "=== PLOOGUE PATTERN MATCH DETAILS ==="
echo "Addr | Prologue | Ret? | Calls? | Approx Size | Classification"
echo "---------------------------------------------------------------"

while IFS= read -r addr; do
  start=$((16#$addr))
  # Read 200 bytes from function start
  end=$((start + 200))
  end_hex=$(printf '%x' $end)
  disasm=$(objdump -d --start-address=0x$addr --stop-address=0x$end_hex "$bin" 2>/dev/null)
  
  # Get first 2 instructions
  first_two=$(echo "$disasm" | grep -E '^\s+[0-9a-f]+:' | head -2 | sed 's/^[ \t]*[0-9a-f]*:\s*//')
  first_inst_clean=$(echo "$disasm" | grep -E '^\s+[0-9a-f]+:' | head -1 | sed 's/^[ \t]*[0-9a-f]*:\s*//')
  
  # Check for ret
  has_ret=$(echo "$disasm" | grep -c -E 'ret$|retn$|retq$')
  ret_symbol=$([ "$has_ret" -gt 0 ] && echo "Y" || echo "N")
  
  # Check for direct call instructions
  has_call=$(echo "$disasm" | grep -c -E 'call')
  call_symbol=$([ "$has_call" -gt 0 ] && echo "Y" || echo "N")
  
  # Count instructions
  instrs=$(echo "$disasm" | grep -c -E '^\s+[0-9a-f]+:')
  
  # Determine if it has a standard MSVC x64 prologue
  prologue_type=""
  case "$first_inst_clean" in
    *"mov"*"0x8(%rsp)"*) prologue_type="mov[rsp+8]" ;;
    *"mov"*"0x10(%rsp)"*) prologue_type="mov[rsp+10h]" ;;
    *"push"*"%rbx"*) prologue_type="push rbx" ;;
    *"push"*"%rbp"*) prologue_type="push rbp" ;;
    *"push"*"%rdi"*) prologue_type="push rdi" ;;
    *"sub"*"%rsp"*) prologue_type="sub rsp" ;;
    *) prologue_type="other: $first_inst_clean" ;;
  esac
  
  if [ "$has_ret" -gt 0 ] || [ "$has_call" -gt 0 ]; then
    echo "  $addr | $prologue_type | $ret_symbol | $call_symbol | ~${instrs}i | CONFIRMED_FUNCTION"
    confirmed=$((confirmed + 1))
  else
    echo "  $addr | $prologue_type | $ret_symbol | $call_symbol | ~${instrs}i | SUSPICIOUS"
    suspect=$((suspect + 1))
  fi
done < /tmp/fs_addrs.txt

echo ""
echo "=== SUMMARY ==="
echo "Total func_start functions: $total"
echo "CONFIRMED_FUNCTION: $confirmed"
echo "SUSPICIOUS (no ret, no call): $suspect"
echo "Precision: $(( (confirmed * 100) / total ))%"
