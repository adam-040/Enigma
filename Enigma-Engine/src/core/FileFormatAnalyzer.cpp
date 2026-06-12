#include <ghidra/FileFormatAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/ProgramFragment.h>
#include <ghidra/ProgramModule.h>
#include <ghidra/TreeManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Memory.h>
#include <ghidra/Group.h>
#include <ghidra/AnalysisPriority.h>
#include <ghidra/AddressSpace.h>

namespace ghidra {

FileFormatAnalyzer::FileFormatAnalyzer(const std::string& name, const std::string& description,
                                       AnalyzerType type)
    : AbstractAnalyzer(name, description, type) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
}

bool FileFormatAnalyzer::added(Program* program, const AddressSetView& set,
                                TaskMonitor* monitor, MessageLog& log) {
    try {
        return analyze(program, set, monitor, log);
    }
    catch (const std::exception& e) {
        log.append(std::string("Exception: ") + e.what());
    }
    catch (...) {
        log.append("Unknown exception in FileFormatAnalyzer");
    }
    return false;
}

Address FileFormatAnalyzer::toAddr(Program* program, uint64_t offset) {
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    return Address(space, static_cast<int64_t>(offset));
}

Data* FileFormatAnalyzer::createData(Program* program, const Address& address, DataType* datatype) {
    return program->getListing()->createData(address, datatype);
}

ProgramFragment* FileFormatAnalyzer::createFragment(Program* program, const std::string& fragmentName,
                                                     const Address& start, const Address& end) {
    ProgramModule* rootModule = program->getTreeManager()->getDefaultRootModule();
    if (!rootModule) return nullptr;
    ProgramFragment* fragment = rootModule->createFragment(fragmentName);
    if (!fragment) return nullptr;
    fragment->move(start, end);
    return fragment;
}

void FileFormatAnalyzer::removeEmptyFragments(Program* program) {
    ProgramModule* rootModule = program->getTreeManager()->getDefaultRootModule();
    if (!rootModule) return;
    std::vector<Group*> children = rootModule->getChildren();
    for (Group* child : children) {
        ProgramFragment* fragment = dynamic_cast<ProgramFragment*>(child);
        if (fragment && fragment->isEmpty()) {
            rootModule->removeChild(fragment->getName());
        }
    }
}

void FileFormatAnalyzer::changeDataSettings(Program* program, TaskMonitor* monitor) {
    if (monitor) monitor->setMessage("Changing data settings...");
    Address address = program->getMinAddress();
    Memory* memory = program->getMemory();
    while (monitor && !monitor->isCancelled()) {
        Data* data = getDataAt(program, address);
        if (!data) {
            data = getDataAfter(program, address);
        }
        if (!data) break;
        int numComponents = data->getNumComponents();
        for (int i = 0; i < numComponents; ++i) {
            if (monitor && monitor->isCancelled()) break;
            Data* component = data->getComponent(i);
            int len = component->getLength();
            uint8_t* bytes = new uint8_t[len];
            if (memory->getBytes(component->getAddress(), bytes, len) == len) {
                bool isAscii = true;
                for (int j = 0; j < len; ++j) {
                    if (bytes[j] < ' ' || bytes[j] > '~') { isAscii = false; break; }
                }
                if (isAscii && len > 1) {
                    changeFormatToString(component);
                }
            }
            delete[] bytes;
        }
        address = Address(address.getAddressSpace(), address.getOffset() + data->getLength());
    }
}

void FileFormatAnalyzer::changeFormatToString(Data* data) {
    (void)data;
    // Format settings are not yet implemented in C++ port
}

Data* FileFormatAnalyzer::getDataAt(Program* program, const Address& address) {
    return program->getListing()->getDataAt(address);
}

Data* FileFormatAnalyzer::getDataAfter(Program* program, const Address& address) {
    (void)program;
    (void)address;
    return nullptr; // Not yet implemented
}

bool FileFormatAnalyzer::setPlateComment(Program* program, const Address& address,
                                          const std::string& comment) {
    Data* data = getDataAt(program, address);
    if (data) {
        data->setComment(comment);
        return true;
    }
    return false;
}

} // namespace ghidra
