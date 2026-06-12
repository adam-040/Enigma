#include <ghidra/DexMarkupDataAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataType.h>
#include <ghidra/Structure.h>
#include <ghidra/DataTypeComponent.h>
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
#include <algorithm>
#include <string>
#include <cstdint>

namespace ghidra {

static bool isDexOrCdex(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return (magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A) ||
           (magic[0] == 0x63 && magic[1] == 0x64 && magic[2] == 0x65 && magic[3] == 0x78);
}

DexMarkupDataAnalyzer::DexMarkupDataAnalyzer()
    : AbstractAnalyzer("Android DEX/CDEX Data Markup",
                       "Android DEX/CDEX Data Markup.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION);
    setDefaultEnablement(true);
}

bool DexMarkupDataAnalyzer::canAnalyze(Program* program) const {
    return isDexOrCdex(program);
}

bool DexMarkupDataAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

static void processData(Program* program, Data* data, int headerLength,
                         ReferenceManager* refMgr, Memory* memory, TaskMonitor* monitor) {
    DataType* baseType = data->getBaseDataType();
    if (!baseType) return;

    Structure* structType = dynamic_cast<Structure*>(baseType);
    if (!structType) return;

    auto typeComponents = structType->getComponents();
    int numComps = data->getNumComponents();

    for (int i = 0; i < numComps; ++i) {
        if (monitor && monitor->isCancelled()) return;

        Data* component = data->getComponent(i);
        if (!component) continue;

        if (component->getNumComponents() > 0) {
            processData(program, component, headerLength, refMgr, memory, monitor);
        }

        if (i >= static_cast<int>(typeComponents.size())) continue;
        DataTypeComponent* dtc = typeComponents[i];
        if (!dtc) continue;

        std::string fieldName = dtc->getFieldName();
        std::string lowerName = fieldName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        if (lowerName.find("offset") == std::string::npos) continue;

        Address compAddr = component->getAddress();
        if (!compAddr.isValid()) continue;

        auto existingRefs = refMgr->getReferencesFrom(compAddr);
        if (!existingRefs.empty()) continue;

        int compLength = dtc->getLength();
        if (compLength < 1) continue;

        uint32_t value = 0;
        int bytesToRead = (compLength < 4) ? compLength : 4;
        if (memory->getBytes(compAddr, reinterpret_cast<uint8_t*>(&value), bytesToRead) != bytesToRead) continue;

        if (value < static_cast<uint32_t>(headerLength)) continue;

        Address destAddr(compAddr.getAddressSpace(), static_cast<uint64_t>(value));
        refMgr->addMemoryReference(compAddr, destAddr, &RefTypes::DATA, SourceType::ANALYSIS, 0);
    }
}

bool DexMarkupDataAnalyzer::added(Program* program, const AddressSetView& set,
                                    TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    auto* memory = program->getMemory();
    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    if (!memory || !listing || !refMgr) return false;

    if (monitor) monitor->setMessage("Marking up DEX data...");

    int headerLength = 0x70;

    std::vector<Data*> allData = listing->getData(set);
    for (Data* data : allData) {
        if (monitor && monitor->isCancelled()) return false;

        if (!data || !data->isStructure()) continue;
        if (data->getAddress().getOffset() == 0x0) continue;

        processData(program, data, headerLength, refMgr, memory, monitor);
    }

    return true;
}

} // namespace ghidra
