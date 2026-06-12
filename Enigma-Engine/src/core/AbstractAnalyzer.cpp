#include <ghidra/AbstractAnalyzer.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

const AddressSet AbstractAnalyzer::EMPTY_ADDRESS_SET;

AbstractAnalyzer::AbstractAnalyzer(const std::string& name, const std::string& description, AnalyzerType type)
    : name_(name), description_(description), type_(type) {}

AddressSetView* AbstractAnalyzer::analyzeLocation(Program* program, const Address& location,
                                                  const AddressSetView& set, TaskMonitor* monitor) {
    MessageLog log;
    AddressSet single(location, location);
    if (canAnalyze(program) && getDefaultEnablement(program)) {
        added(program, single, monitor, log);
    }
    return nullptr;
}

AddressSetView* AbstractAnalyzer::runParallelAddressAnalysis(Program* program,
                                                              const std::vector<Address>& addresses,
                                                              const AddressSetView& set,
                                                              int threadCount,
                                                              TaskMonitor* monitor) {
    AddressSet unanalyzed;
    MessageLog log;
    for (const Address& addr : addresses) {
        if (monitor && monitor->isCancelled()) break;
        AddressSet single(addr, addr);
        if (!added(program, single, monitor, log)) {
            unanalyzed.add(addr);
        }
    }
    if (unanalyzed.isEmpty()) return nullptr;
    return new AddressSet(unanalyzed);
}

} // namespace ghidra
