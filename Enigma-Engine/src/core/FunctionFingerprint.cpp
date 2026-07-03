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
#include <ghidra/LanguageID.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <capstone/arm64.h>
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

// Detect Capstone architecture from program language ID.
bool isArm64Program(Program* program) {
    if (!program) return false;
    std::string lid = program->getLanguageID().getIdAsString();
    return lid.find("AARCH64") != std::string::npos ||
           lid.find("aarch64") != std::string::npos ||
           lid.find("ARM64") != std::string::npos;
}

// ── V2 helpers ──────────────────────────────────────────────────────────────

// Disassemble up to maxInstr instructions from entry point using Capstone.
struct CsInstr {
    std::string mnemonic;
    const uint8_t* bytes;
    int length;
};

std::vector<CsInstr> capstoneDisassemble(const uint8_t* codeBuf, int bytesRead,
                                          uint64_t baseAddr, int maxInstr,
                                          cs_arch arch, cs_mode mode) {
    std::vector<CsInstr> result;
    if (bytesRead < 1) return result;

    csh handle;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
        return result;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insns = nullptr;
    size_t count = cs_disasm(handle, codeBuf, bytesRead,
                             baseAddr, maxInstr, &insns);
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
// Supports both x86 and ARM64 mnemonics.
bool isCallOrJump(const std::string& mn) {
    // x86
    if (mn == "call" || mn == "jmp") return true;
    if (mn.size() >= 2 && mn[0] == 'j' && mn != "jmp") return true; // je, jne, jg, jge, jl, jle, ja, jae, jb, jbe, jo, jno, js, jns, jp, jnp, jz, jnz
    if (mn == "loop" || mn == "loope" || mn == "loopne") return true;
    // ARM64
    if (mn == "b" || mn == "bl" || mn == "blr" || mn == "br" || mn == "ret") return true;
    if (mn.rfind("b.", 0) == 0) return true; // b.eq, b.ne, b.lt, etc.
    if (mn == "cbz" || mn == "cbnz" || mn == "tbz" || mn == "tbnz") return true;
    return false;
}

} // anonymous namespace

FunctionFingerprint FunctionFingerprinter::compute(Function* func, Program* program) {
    FunctionFingerprint fp;
    if (!func || !program) return fp;

    Memory* memory = program->getMemory();
    if (!memory) return fp;

    Address entry = func->getEntryPoint();
    if (!entry.isValid()) return fp;

    // Determine body size and read all available bytes.
    // Use getNumAddresses() as an estimate; cap at 1 MB to avoid pathological cases.
    int64_t bodySize = func->getBody().getNumAddresses();
    if (bodySize < 1) bodySize = 256;
    if (bodySize > 1024 * 1024) bodySize = 1024 * 1024;

    std::vector<uint8_t> bodyBuf(static_cast<size_t>(bodySize));
    int bytesRead = memory->getBytes(entry, bodyBuf.data(), static_cast<int>(bodySize));
    if (bytesRead < 1) return fp;

    // ── V1: raw-byte FNV-1a (backward-compatible with FidHasher) ────────────
    // fullHash = all body bytes (matching the fixed ingest tool)
    fp.v1.fullHash  = fnv1a64(bodyBuf.data(), bytesRead);
    // shortHash = first 32 bytes only (FLIRT-compatible quick filter)
    int shortLen = std::min(bytesRead, MAX_SHORT_HASH_BYTES);
    fp.v1.shortHash = fnv1a64(bodyBuf.data(), shortLen);
    fp.v1.mnemHash  = 0;
    fp.v1.callHash  = 0;

    // ── V2: Capstone instruction-aware hashing ──────────────────────────────
    // Select architecture from program language
    cs_arch csArch = CS_ARCH_X86;
    cs_mode csMode = CS_MODE_64;
    if (isArm64Program(program)) {
        csArch = CS_ARCH_ARM64;
        csMode = CS_MODE_ARM;
    }

    auto instrs = capstoneDisassemble(bodyBuf.data(), bytesRead,
                                       entry.getOffset(), 32,
                                       csArch, csMode);
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
