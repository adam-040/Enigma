#include <ghidra/FunctionDiscoveryAnalyzerAdapter.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/FunctionManager.h>

namespace ghidra {

FunctionDiscoveryAnalyzerAdapter::FunctionDiscoveryAnalyzerAdapter(BinaryLoader* loader, FunctionDiscoveryOptions options)
    : loader_(loader), options_(options) {}

bool FunctionDiscoveryAnalyzerAdapter::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (!loader_) return true;

    FunctionDiscoveryAnalyzer fda(options_);
    fda.analyzeLoader(*loader_);

    auto* manager = program->getFunctionManager();
    auto* addrFactory = program->getAddressFactory();
    if (manager && addrFactory) {
        auto* codeSpace = const_cast<AddressSpace*>(addrFactory->getDefaultAddressSpace());
        fda.applyTo(*manager, codeSpace);
    }

    return true;
}

} // namespace ghidra
