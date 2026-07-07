#include <ghidra/pcode/ExtCodeBlockImpl.h>
#include <ghidra/pcode/CodeBlockModel.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Program.h>

namespace ghidra::pcode {

ExtCodeBlockImpl::ExtCodeBlockImpl(CodeBlockModel* model, const Address& extAddr)
    : AddressSet(extAddr), model_(model), extAddr_(extAddr) {
    if (!extAddr.isExternalAddress()) {
        throw std::invalid_argument("Expected external address");
    }
}

std::string ExtCodeBlockImpl::getName() const {
    auto* symTable = model_->getProgram()->getSymbolTable();
    Symbol* s = symTable->getPrimarySymbol(extAddr_);
    if (s) return s->getName();
    return extAddr_.toString();
}

CodeBlockReferenceIterator* ExtCodeBlockImpl::getDestinations(TaskMonitor* monitor) {
    return new EmptyCodeBlockReferenceIterator();
}

int ExtCodeBlockImpl::getNumSources(TaskMonitor* monitor) {
    return model_->getNumSources(this, monitor);
}

CodeBlockReferenceIterator* ExtCodeBlockImpl::getSources(TaskMonitor* monitor) {
    return model_->getSources(this, monitor);
}

} // namespace ghidra::pcode
