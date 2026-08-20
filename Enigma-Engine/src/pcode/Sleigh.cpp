#include <ghidra/Sleigh.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/BlockGraph.h>
#include <ghidra/Disassembler.h>
#include <capstone/capstone.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cctype>

namespace ghidra {

Sleigh::Sleigh(LoadImage* ld, const std::string& slaPath)
    : Translate(ld, 4, false), slaFile(slaPath), initialized(false),
      maxInstructionBytes(16), capstoneHandle_(0), capstoneInitialized_(false),
      archName_("x86"), archBitness_(64) {
    contextDatabase.addContext("flow", 0, 4);
    contextDatabase.addContext("addr", 0, 64);
    contextDatabase.setDefault("flow", 0);
}

Sleigh::~Sleigh() {
    if (capstoneHandle_ != 0) {
        cs_close(reinterpret_cast<csh*>(&capstoneHandle_));
    }
}

bool Sleigh::initialize() {
    // Initialize Capstone
    cs_arch csArch = CS_ARCH_X86;
    cs_mode csMode = CS_MODE_64;

    std::string archLower = archName_;
    std::transform(archLower.begin(), archLower.end(), archLower.begin(),
                   [](unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); });

    if (archLower.find("x86") != std::string::npos || archLower == "i386" || archLower == "i686") {
        csArch = CS_ARCH_X86;
        csMode = (archBitness_ == 64) ? CS_MODE_64 : CS_MODE_32;
        codeAlign = 1;
    } else if (archLower.find("aarch64") != std::string::npos || archLower.find("arm64") != std::string::npos) {
        csArch = CS_ARCH_ARM64;
        csMode = CS_MODE_ARM;
        codeAlign = 4;
    } else if (archLower.find("arm") != std::string::npos) {
        csArch = CS_ARCH_ARM;
        csMode = (archBitness_ == 64) ? CS_MODE_ARM : CS_MODE_ARM;
        if (archBigEndian_) csMode = static_cast<cs_mode>(csMode | CS_MODE_BIG_ENDIAN);
        codeAlign = 4;
    } else if (archLower.find("mips") != std::string::npos) {
        csArch = CS_ARCH_MIPS;
        csMode = (archBitness_ == 64) ? CS_MODE_MIPS64 : CS_MODE_MIPS32;
        if (archBigEndian_) csMode = static_cast<cs_mode>(csMode | CS_MODE_BIG_ENDIAN);
        codeAlign = 4;
    } else if (archLower.find("ppc") != std::string::npos || archLower.find("powerpc") != std::string::npos) {
        csArch = CS_ARCH_PPC;
        csMode = (archBitness_ == 64) ? CS_MODE_64 : CS_MODE_32;
        if (archBigEndian_) csMode = static_cast<cs_mode>(csMode | CS_MODE_BIG_ENDIAN);
        codeAlign = 4;
    } else {
        return false;
    }

    if (cs_open(csArch, csMode, reinterpret_cast<csh*>(&capstoneHandle_)) != CS_ERR_OK) {
        capstoneInitialized_ = false;
        initialized = false;
        return false;
    }
    cs_option(reinterpret_cast<csh&>(capstoneHandle_), CS_OPT_DETAIL, CS_OPT_ON);
    capstoneInitialized_ = true;

    // Initialize the pcode mapper
    mapper_.initialize(archName_);

    initialized = true;
    return true;
}

void Sleigh::setArchitecture(const std::string& arch, int bitness) {
    archName_ = arch;
    archBitness_ = bitness;
    pointerSize = bitness / 8;
}

bool Sleigh::decodeInstruction(const Address& addr, DisassembledInstruction& di) const {
    di = DisassembledInstruction();
    di.address = addr;
    di.length = 0;
    di.byteCount = 0;
    di.flowType = const_cast<FlowType*>(&RefTypes::FALL_THROUGH);

    if (!initialized || capstoneHandle_ == 0) {
        return false;
    }

    uint8_t rawBytes[16];
    std::memset(rawBytes, 0, sizeof(rawBytes));
    try {
        loader->loadFill(rawBytes, static_cast<int4>(sizeof(rawBytes)), addr);
    } catch (...) {
        return false;
    }

    csh handle = static_cast<csh>(capstoneHandle_);
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle,
                             rawBytes, sizeof(rawBytes),
                             addr.getOffset(), 1, &insn);
    if (count == 0 || !insn) {
        return false;
    }

    di.mnemonic = insn->mnemonic ? insn->mnemonic : "";
    di.length = static_cast<int>(insn->size);
    di.byteCount = static_cast<int>(insn->size);

    if (insn->op_str && insn->op_str[0] != '\0') {
        std::string ops = insn->op_str;
        size_t pos = 0;
        while ((pos = ops.find(',')) != std::string::npos) {
            std::string op = ops.substr(0, pos);
            op.erase(op.begin(), std::find_if(op.begin(), op.end(), [](unsigned char c) { return !std::isspace(c); }));
            di.operands.push_back(op);
            ops.erase(0, pos + 1);
        }
        ops.erase(ops.begin(), std::find_if(ops.begin(), ops.end(), [](unsigned char c) { return !std::isspace(c); }));
        if (!ops.empty()) {
            di.operands.push_back(ops);
        }
    }

    for (int i = 0; i < di.byteCount && i < 16; i++) {
        di.bytes[i] = insn->bytes[i];
    }

    di.flowType = Disassembler::determineFlowType(di.mnemonic, di.operands);
    cs_free(insn, count);
    return di.length > 0;
}

int4 Sleigh::instructionLength(const Address& addr) const {
    if (!initialized) return 0;
    DisassembledInstruction di;
    return decodeInstruction(addr, di) ? di.length : 0;
}

int4 Sleigh::printAssembly(const Address& addr, std::string& output) const {
    if (!initialized) {
        output = "uninitialized";
        return 0;
    }
    DisassembledInstruction di;
    if (!decodeInstruction(addr, di)) {
        output = "unknown";
        return 0;
    }
    output = di.mnemonic;
    if (!di.operands.empty()) {
        output += " ";
        for (size_t i = 0; i < di.operands.size(); ++i) {
            if (i != 0) output += ", ";
            output += di.operands[i];
        }
    }
    return di.length;
}

int4 Sleigh::oneInstruction(Funcdata& fd, const Address& addr) {
    stats.numInstructions++;

    if (!initialized || capstoneHandle_ == 0) {
        // Not initialized — return 0 (no op created)
        return 0;
    }

    // Read bytes from memory
    uint8_t rawBytes[16];
    std::memset(rawBytes, 0, sizeof(rawBytes));
    try {
        loader->loadFill(rawBytes, static_cast<int4>(sizeof(rawBytes)), addr);
    } catch (...) {
        return 0;
    }

    // Disassemble with Capstone
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(reinterpret_cast<csh&>(capstoneHandle_),
                             rawBytes, sizeof(rawBytes),
                             addr.getOffset(), 1, &insn);

    if (count == 0 || !insn) {
        return 0;
    }

    // Build DisassembledInstruction from Capstone output
    DisassembledInstruction di;
    di.address = addr;
    di.mnemonic = insn->mnemonic ? insn->mnemonic : "";
    di.length = static_cast<int>(insn->size);
    di.byteCount = static_cast<int>(insn->size);

    // Parse operands
    if (insn->op_str && insn->op_str[0] != '\0') {
        std::string ops = insn->op_str;
        size_t pos = 0;
        while ((pos = ops.find(',')) != std::string::npos) {
            di.operands.push_back(ops.substr(0, pos));
            ops.erase(0, pos + 1);
        }
        if (!ops.empty()) {
            // trim leading space
            if (!ops.empty() && ops[0] == ' ') ops.erase(0, 1);
            if (!ops.empty()) di.operands.push_back(ops);
        }
    }

    // Store raw bytes
    for (int i = 0; i < di.byteCount && i < 16; i++) {
        di.bytes[i] = insn->bytes[i];
    }

    // Determine flow type
    di.flowType = Disassembler::determineFlowType(di.mnemonic, di.operands);

    // Free Capstone insn
    cs_free(insn, count);

    // Map instruction to pcode ops
    Address blockAddr = addr;
    try {
        mapper_.mapInstruction(di, fd, blockAddr);
    } catch (const std::exception& e) {
        std::cerr << "  [mapper exception for '" << di.mnemonic << "': " << e.what() << "]\n";
        throw;
    }

    // Update stats (approximate: count ops created in funcdata)
    // We can't easily diff opList before/after, so approximate
    stats.numPcodeOps += 5; // average

    return di.length > 0 ? di.length : codeAlign;
}

void Sleigh::setContextDefault(const std::string& name, uintb value) {
    contextDatabase.setDefault(name, value);
}

void Sleigh::allowContextSet(bool val) {
    (void)val;
}

bool Sleigh::hasFallthrough(const Address& addr) const {
    DisassembledInstruction di;
    return decodeInstruction(addr, di) && di.flowType && di.flowType->hasFallthrough();
}

Address Sleigh::getFallthrough(const Address& addr) const {
    if (!initialized) return Address::NO_ADDRESS;
    DisassembledInstruction di;
    if (!decodeInstruction(addr, di) || !di.flowType || !di.flowType->hasFallthrough()) {
        return Address::NO_ADDRESS;
    }
    auto* space = addr.getAddressSpace();
    return Address(space, addr.getOffset() + di.length);
}

bool Sleigh::isBranchFallthrough(const Address& addr) const {
    DisassembledInstruction di;
    return decodeInstruction(addr, di) && di.flowType &&
           di.flowType->isJump() && di.flowType->hasFallthrough();
}

bool Sleigh::isCallInstruction(const Address& addr) const {
    DisassembledInstruction di;
    return decodeInstruction(addr, di) && di.flowType && di.flowType->isCall();
}

bool Sleigh::isReturnInstruction(const Address& addr) const {
    DisassembledInstruction di;
    return decodeInstruction(addr, di) && di.flowType && di.flowType->isTerminal();
}

} // namespace ghidra
