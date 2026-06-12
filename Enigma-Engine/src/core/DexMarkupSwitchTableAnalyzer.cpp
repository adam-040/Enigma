#include <ghidra/DexMarkupSwitchTableAnalyzer.h>
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
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/SourceType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Namespace.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <ghidra/Scalar.h>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace ghidra {

static constexpr uint16_t PACKED_SWITCH_MAGIC = 0x0100;
static constexpr uint16_t SPARSE_SWITCH_MAGIC = 0x0200;

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

static void processPacked(Program* program, const Address& instrAddr,
                           uint16_t size, int32_t firstKey,
                           const std::vector<uint32_t>& targets,
                           TaskMonitor* monitor) {
    std::ostringstream nsName;
    nsName << "pswitch_0x" << std::hex << instrAddr.getOffset();
    Namespace nameSpace(nsName.str());

    for (int i = 0; i < static_cast<int>(targets.size()); ++i) {
        if (monitor && monitor->isCancelled()) return;

        std::ostringstream caseName;
        caseName << "case_0x" << std::hex << (firstKey + i);

        int32_t targetOffset = static_cast<int32_t>(targets[i]);
        Address caseAddr = instrAddr.add(targetOffset * 2);

        program->getSymbolTable()->createLabel(caseAddr, caseName.str(), &nameSpace, SourceType::ANALYSIS);
        program->getReferenceManager()->addMemoryReference(instrAddr, caseAddr,
            &RefTypes::COMPUTED_JUMP, SourceType::ANALYSIS, -1);
    }
}

static void processSparse(Program* program, const Address& instrAddr,
                           uint16_t size,
                           const std::vector<uint32_t>& keys,
                           const std::vector<uint32_t>& targets,
                           TaskMonitor* monitor) {
    std::ostringstream nsName;
    nsName << "sswitch_0x" << std::hex << instrAddr.getOffset();
    Namespace nameSpace(nsName.str());

    for (int i = 0; i < static_cast<int>(size); ++i) {
        if (monitor && monitor->isCancelled()) return;

        std::ostringstream caseName;
        caseName << "case_0x" << std::hex << keys[i];

        int32_t targetOffset = static_cast<int32_t>(targets[i]);
        Address caseAddr = instrAddr.add(targetOffset * 2);

        program->getSymbolTable()->createLabel(caseAddr, caseName.str(), &nameSpace, SourceType::ANALYSIS);
        program->getReferenceManager()->addMemoryReference(instrAddr, caseAddr,
            &RefTypes::COMPUTED_JUMP, SourceType::ANALYSIS, -1);
    }
}

DexMarkupSwitchTableAnalyzer::DexMarkupSwitchTableAnalyzer()
    : AbstractAnalyzer("Android DEX/CDEX Switch Table Markup",
                       "Android DEX/CDEX Switch Table Markup.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION);
    setDefaultEnablement(true);
}

bool DexMarkupSwitchTableAnalyzer::canAnalyze(Program* program) const {
    return isDexOrCdex(program);
}

bool DexMarkupSwitchTableAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DexMarkupSwitchTableAnalyzer::added(Program* program, const AddressSetView& set,
                                          TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    auto* memory = program->getMemory();
    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    auto* dtm = program->getDataTypeManager();
    if (!memory || !listing || !refMgr || !dtm) return false;

    if (monitor) monitor->setMessage("Marking up DEX switch tables...");

    std::vector<Instruction*> instructions = listing->getInstructions(set);
    for (Instruction* instruction : instructions) {
        if (monitor && monitor->isCancelled()) return false;
        if (!instruction) continue;

        const std::string& mnemonic = instruction->getMnemonicString();

        if (mnemonic.rfind("packed_switch", 0) == 0) {
            auto existingRefs = refMgr->getReferencesFrom(instruction->getAddress(), -1);
            if (!existingRefs.empty()) continue;

            const std::vector<Scalar*>& scalars = instruction->getScalars();
            if (scalars.size() < 2) continue;
            Scalar* scalar = scalars[1];
            if (!scalar) continue;

            uint64_t offset = static_cast<uint64_t>(scalar->getUnsignedValue()) * 2;
            Address switchAddr = instruction->getAddress().add(offset);

            uint16_t magic = readUint16LE(memory, switchAddr);
            if (magic != PACKED_SWITCH_MAGIC) {
                log.append("invalid packed switch at " + switchAddr.toString());
                continue;
            }

            uint16_t size = readUint16LE(memory, switchAddr.add(2));
            int32_t firstKey = static_cast<int32_t>(readUint32LE(memory, switchAddr.add(4)));

            std::vector<uint32_t> targets(size);
            for (int i = 0; i < static_cast<int>(size); ++i) {
                targets[i] = readUint32LE(memory, switchAddr.add(8 + i * 4));
            }

            refMgr->addMemoryReference(instruction->getAddress(), switchAddr,
                &RefTypes::DATA, SourceType::ANALYSIS, 1);

            auto psType = std::make_unique<StructureDataType>("packed_switch_payload_" + std::to_string(size), 0, dtm);
            psType->add(&WordDataType::dataType(), "ident", "");
            psType->add(&WordDataType::dataType(), "size", "");
            psType->add(&DWordDataType::dataType(), "first_key", "");
            psType->add(new ArrayDataType(&DWordDataType::dataType(), size, 4, dtm), "targets", "");

            DataType* resolved = dtm->resolve(psType.get(), nullptr);
            if (resolved) {
                listing->createData(switchAddr, resolved);
            }

            processPacked(program, instruction->getAddress(), size, firstKey, targets, monitor);
        }
        else if (mnemonic.rfind("sparse_switch", 0) == 0) {
            auto existingRefs = refMgr->getReferencesFrom(instruction->getAddress(), -1);
            if (!existingRefs.empty()) continue;

            const std::vector<Scalar*>& scalars = instruction->getScalars();
            if (scalars.size() < 2) continue;
            Scalar* scalar = scalars[1];
            if (!scalar) continue;

            uint64_t offset = static_cast<uint64_t>(scalar->getUnsignedValue()) * 2;
            Address switchAddr = instruction->getAddress().add(offset);

            uint16_t magic = readUint16LE(memory, switchAddr);
            if (magic != SPARSE_SWITCH_MAGIC) {
                log.append("invalid sparse switch at " + switchAddr.toString());
                continue;
            }

            uint16_t size = readUint16LE(memory, switchAddr.add(2));

            std::vector<uint32_t> keys(size);
            for (int i = 0; i < static_cast<int>(size); ++i) {
                keys[i] = readUint32LE(memory, switchAddr.add(4 + i * 4));
            }

            std::vector<uint32_t> targets(size);
            int keyArraySize = static_cast<int>(size) * 4;
            for (int i = 0; i < static_cast<int>(size); ++i) {
                targets[i] = readUint32LE(memory, switchAddr.add(4 + keyArraySize + i * 4));
            }

            refMgr->addMemoryReference(instruction->getAddress(), switchAddr,
                &RefTypes::DATA, SourceType::ANALYSIS, 1);

            auto ssType = std::make_unique<StructureDataType>("sparse_switch_payload_" + std::to_string(size), 0, dtm);
            ssType->add(&WordDataType::dataType(), "ident", "");
            ssType->add(&WordDataType::dataType(), "size", "");
            ssType->add(new ArrayDataType(&DWordDataType::dataType(), size, 4, dtm), "keys", "");
            ssType->add(new ArrayDataType(&DWordDataType::dataType(), size, 4, dtm), "targets", "");

            DataType* resolved = dtm->resolve(ssType.get(), nullptr);
            if (resolved) {
                listing->createData(switchAddr, resolved);
            }

            processSparse(program, instruction->getAddress(), size, keys, targets, monitor);
        }
    }

    return true;
}

} // namespace ghidra
