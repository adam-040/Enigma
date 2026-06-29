/* ###
 * IP: GHIDRA
 *
 * FunctionFingerprint — compute V1 (raw-byte) + V2 (Capstone instruction-aware) fingerprints.
 */
#include <ghidra/FunctionFingerprint.h>
#include <ghidra/Function.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/FNV1a64.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

namespace ghidra {

namespace {

uint64_t fnv1a64(const uint8_t* data, int length) {
    FNV1a64 h;
    h.update(data, length);
    return h.digest();
}

// ── V2 helpers ──────────────────────────────────────────────────────────────

// Disassemble up to maxInstr instructions from entry point using Capstone.
struct CsInstr {
    std::string mnemonic;
    const uint8_t* bytes;
    int length;
};

std::vector<CsInstr> capstoneDisassemble(Memory* memory, Address entry, int maxInstr) {
    std::vector<CsInstr> result;
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return result;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Read up to 64 bytes from entry
    uint8_t codeBuf[64];
    int bytesRead = memory->getBytes(entry, codeBuf, sizeof(codeBuf));
    if (bytesRead < 1) { cs_close(&handle); return result; }

    cs_insn* insns = nullptr;
    size_t count = cs_disasm(handle, codeBuf, bytesRead,
                             entry.getOffset(), maxInstr, &insns);
    for (size_t i = 0; i < count; i++) {
        CsInstr ci;
        ci.mnemonic = insns[i].mnemonic;
        ci.bytes = insns[i].bytes;
        ci.length = static_cast<int>(insns[i].size);
        result.push_back(ci);
    }
    cs_free(insns, count);
    cs_close(&handle);
    return result;
}

// Check if mnemonic is a call or jump (for call-independent hashing).
bool isCallOrJump(const std::string& mn) {
    return mn == "call" || mn == "jmp" || mn == "je" || mn == "jne" ||
           mn == "jz" || mn == "jnz" || mn == "jg" || mn == "jge" ||
           mn == "jl" || mn == "jle" || mn == "ja" || mn == "jae" ||
           mn == "jb" || mn == "jbe" || mn == "jo" || mn == "jno" ||
           mn == "js" || mn == "jns" || mn == "jp" || mn == "jnp" ||
           mn == "loop" || mn == "loope" || mn == "loopne";
}

} // anonymous namespace

FunctionFingerprint FunctionFingerprinter::compute(Function* func, Program* program) {
    FunctionFingerprint fp;
    if (!func || !program) return fp;

    Memory* memory = program->getMemory();
    if (!memory) return fp;

    Address entry = func->getEntryPoint();
    if (!entry.isValid()) return fp;

    // ── V1: raw-byte FNV-1a (backward-compatible with FidHasher) ────────────
    uint8_t buf[MAX_SHORT_HASH_BYTES];
    int bytesRead = memory->getBytes(entry, buf, MAX_SHORT_HASH_BYTES);
    if (bytesRead < 1) return fp;

    uint64_t hash = fnv1a64(buf, bytesRead);
    fp.v1.fullHash  = hash;
    fp.v1.shortHash = hash;
    fp.v1.mnemHash  = 0;
    fp.v1.callHash  = 0;

    // ── V2: Capstone instruction-aware hashing ──────────────────────────────
    auto instrs = capstoneDisassemble(memory, entry, 32);
    if (!instrs.empty()) {
        // V2 fullHash: hash all mnemonic strings (opcode sequence)
        {
            FNV1a64 h;
            for (auto& ci : instrs) {
                h.updateByte(0); // separator
                h.update(reinterpret_cast<const uint8_t*>(ci.mnemonic.data()),
                         static_cast<int>(ci.mnemonic.size()));
            }
            fp.v2.fullHash = h.digest();
        }

        // V2 shortHash: hash first 8 mnemonics only
        {
            FNV1a64 h;
            int count = 0;
            for (auto& ci : instrs) {
                if (count >= 8) break;
                h.updateByte(0);
                h.update(reinterpret_cast<const uint8_t*>(ci.mnemonic.data()),
                         static_cast<int>(ci.mnemonic.size()));
                count++;
            }
            fp.v2.shortHash = h.digest();
        }

        // V2 mnemHash: mnemonic sequence with calls/jumps excluded
        {
            FNV1a64 h;
            for (auto& ci : instrs) {
                if (isCallOrJump(ci.mnemonic)) continue;
                h.updateByte(0);
                h.update(reinterpret_cast<const uint8_t*>(ci.mnemonic.data()),
                         static_cast<int>(ci.mnemonic.size()));
            }
            fp.v2.mnemHash = h.digest();
        }

        // V2 callHash: first 4 bytes of each instruction (operand prefix)
        {
            FNV1a64 h;
            for (auto& ci : instrs) {
                int n = std::min(4, ci.length);
                h.update(ci.bytes, n);
            }
            fp.v2.callHash = h.digest();
        }
    }

    return fp;
}

} // namespace ghidra
