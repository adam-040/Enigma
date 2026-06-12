#include <ghidra/MingwRelocationAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/RelocationTableImpl.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/SourceType.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

#include <cstdint>
#include <string>

namespace ghidra {

MingwRelocationAnalyzer::MingwRelocationAnalyzer()
    : AbstractAnalyzer("MinGW Relocations",
                       "Identify, markup and apply MinGW pseudo-relocations (must be done immediately after import).",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.before().before().before().before().before());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool MingwRelocationAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable";
}

bool MingwRelocationAnalyzer::added(Program* program, const AddressSetView& set,
                                     TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Address imageBase = program->getImageBase();
    SymbolTable* symTable = program->getSymbolTable();
    if (!symTable) return true;

    Symbol* listStart = symTable->getGlobalSymbol("__MINGW_PSEUDO_RELOC_LIST__", imageBase);
    Symbol* listEnd = symTable->getGlobalSymbol("__MINGW_PSEUDO_RELOC_LIST_END__", imageBase);
    if (!listStart || !listEnd) return true;

    Memory* memory = program->getMemory();
    RelocationTableImpl* relocTable = nullptr;
    {
        auto* rt = dynamic_cast<RelocationTableImpl*>(program->getRelocationTable());
        relocTable = rt;
    }
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory) return true;

    Address startAddr = listStart->getAddress();
    Address endAddr = listEnd->getAddress();
    if (startAddr >= endAddr) return true;

    int64_t byteCount = endAddr.getOffset() - startAddr.getOffset();
    int entryCount = static_cast<int>(byteCount / 8);
    if (entryCount <= 0) return true;

    if (monitor) {
        monitor->setMessage(getName() + ": Applying " + std::to_string(entryCount) + " pseudo-relocations");
        monitor->initialize(entryCount);
    }

    uint32_t baseOffset = static_cast<uint32_t>(imageBase.getOffset());

    for (int i = 0; i < entryCount; ++i) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(i);

        Address entryAddr = startAddr.add(i * 8);
        uint8_t buf[8];
        if (memory->getBytes(entryAddr, buf, 8) != 8) continue;

        uint32_t rva = (static_cast<uint32_t>(buf[0]) << 0) |
                        (static_cast<uint32_t>(buf[1]) << 8) |
                        (static_cast<uint32_t>(buf[2]) << 16) |
                        (static_cast<uint32_t>(buf[3]) << 24);
        uint32_t fixup = (static_cast<uint32_t>(buf[4]) << 0) |
                         (static_cast<uint32_t>(buf[5]) << 8) |
                         (static_cast<uint32_t>(buf[6]) << 16) |
                         (static_cast<uint32_t>(buf[7]) << 24);

        Address targetAddr = imageBase.add(rva);

        uint32_t currentVal = static_cast<uint32_t>(memory->getByte(targetAddr)) |
                              (static_cast<uint32_t>(memory->getByte(targetAddr.add(1))) << 8) |
                              (static_cast<uint32_t>(memory->getByte(targetAddr.add(2))) << 16) |
                              (static_cast<uint32_t>(memory->getByte(targetAddr.add(3))) << 24);

        uint32_t newVal = currentVal + fixup;
        memory->setByte(targetAddr, static_cast<uint8_t>(newVal & 0xFF));
        memory->setByte(targetAddr.add(1), static_cast<uint8_t>((newVal >> 8) & 0xFF));
        memory->setByte(targetAddr.add(2), static_cast<uint8_t>((newVal >> 16) & 0xFF));
        memory->setByte(targetAddr.add(3), static_cast<uint8_t>((newVal >> 24) & 0xFF));

        if (relocTable) {
            relocTable->addRelocation(targetAddr, 0, "MINGW_PSEUDO_RELOC");
        }
        if (refMgr) {
            refMgr->addMemoryReference(targetAddr, entryAddr, &RefTypes::DATA,
                                        SourceType::ANALYSIS, 0);
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Applied " + std::to_string(entryCount) + " pseudo-relocations");
    }

    return true;
}

} // namespace ghidra
