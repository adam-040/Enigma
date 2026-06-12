#include <ghidra/DexMarkupInstructionsAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/SourceType.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <ghidra/Scalar.h>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace ghidra {

static constexpr uint16_t FILLED_ARRAY_MAGIC = 0x0300;

static bool isDexOrCdex(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return (magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A) ||
           (magic[0] == 0x63 && magic[1] == 0x64 && magic[2] == 0x65 && magic[3] == 0x78);
}

static uint16_t readUint16LE(Memory* memory, const Address& addr) {
    uint8_t buf[2] = {0};
    if (memory->getBytes(addr, buf, 2) != 2) return 0;
    return static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8);
}

static uint32_t readUint32LE(Memory* memory, const Address& addr) {
    uint8_t buf[4] = {0};
    if (memory->getBytes(addr, buf, 4) != 4) return 0;
    return static_cast<uint32_t>(buf[0]) |
           (static_cast<uint32_t>(buf[1]) << 8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

DexMarkupInstructionsAnalyzer::DexMarkupInstructionsAnalyzer()
    : AbstractAnalyzer("Android DEX/CDEX Instruction Markup",
                       "Android DEX/CDEX Instruction Markup.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION);
    setDefaultEnablement(true);
}

bool DexMarkupInstructionsAnalyzer::canAnalyze(Program* program) const {
    return isDexOrCdex(program);
}

bool DexMarkupInstructionsAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DexMarkupInstructionsAnalyzer::added(Program* program, const AddressSetView& set,
                                            TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    auto* memory = program->getMemory();
    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    auto* dtm = program->getDataTypeManager();
    if (!memory || !listing || !refMgr || !dtm) return false;

    if (monitor) monitor->setMessage("Marking up DEX instructions...");

    std::vector<Instruction*> instructions = listing->getInstructions(set);
    for (Instruction* instruction : instructions) {
        if (monitor && monitor->isCancelled()) return false;
        if (!instruction) continue;

        const std::string& mnemonic = instruction->getMnemonicString();

        if (mnemonic.rfind("fill_array_data", 0) == 0) {
            const std::vector<Scalar*>& scalars = instruction->getScalars();
            if (scalars.size() < 2) continue;
            Scalar* scalar = scalars[1];
            if (!scalar) continue;

            uint64_t offset = static_cast<uint64_t>(scalar->getUnsignedValue()) * 2;
            Address payloadAddr = instruction->getAddress().add(offset);

            uint16_t magic = readUint16LE(memory, payloadAddr);
            if (magic != FILLED_ARRAY_MAGIC) {
                log.append("invalid filled array at " + payloadAddr.toString());
                continue;
            }

            uint16_t elementWidth = readUint16LE(memory, payloadAddr.add(2));
            uint32_t arraySize = readUint32LE(memory, payloadAddr.add(4));

            int dataSize = static_cast<int>(arraySize) * static_cast<int>(elementWidth);

            refMgr->addMemoryReference(instruction->getAddress(), payloadAddr,
                &RefTypes::DATA, SourceType::ANALYSIS, 1);

            auto faType = std::make_unique<StructureDataType>(
                "filled_array_data_payload_" + std::to_string(elementWidth) + "_" + std::to_string(arraySize),
                0, dtm);
            faType->add(&WordDataType::dataType(), "ident", "");
            faType->add(&WordDataType::dataType(), "element_width", "");
            faType->add(&DWordDataType::dataType(), "size", "");
            faType->add(new ArrayDataType(&ByteDataType::dataType(), dataSize, 1, dtm), "data", "");

            DataType* resolved = dtm->resolve(faType.get(), nullptr);
            if (resolved) {
                listing->createData(payloadAddr, resolved);
            }
        }
    }

    return true;
}

} // namespace ghidra
