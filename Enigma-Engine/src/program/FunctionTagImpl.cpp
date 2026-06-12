#include <ghidra/FunctionTagImpl.h>
#include <ghidra/FunctionTagManager.h>

namespace ghidra {

FunctionTagImpl::FunctionTagImpl(long id, const std::string& name, const std::string& comment, FunctionTagManager* manager)
    : id_(id), name_(name), comment_(comment), manager_(manager) {}

void FunctionTagImpl::deleteTag() {
    if (manager_) {
        manager_->removeFunctionTag(id_);
    }
}

} // namespace ghidra
