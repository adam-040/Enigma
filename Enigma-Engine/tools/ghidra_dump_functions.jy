# ghidra_dump_functions.py
# Ghidra headless script: dump function addresses and names as CSV

import os

from ghidra.program.model.listing import Function

OUTPUT_DIR = r"C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\tools"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "ghidra_script_output.tmp")

fm = currentProgram.getFunctionManager()
count = 0
with open(OUTPUT_FILE, "w") as f:
    functions = fm.getFunctions(True)
    while functions.hasNext():
        func = functions.next()
        addr = func.getEntryPoint().getOffset()
        name = func.getName()
        f.write("0x{:x},{}\n".format(addr, name))
        count += 1
