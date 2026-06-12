#include <ghidra/StackFrameImpl.h>
#include <ghidra/Function.h>
#include <ghidra/VariableImpl.h>
#include <ghidra/DefaultDataType.h>
#include <ghidra/Program.h>
#include <algorithm>

namespace ghidra {

StackFrameImpl::StackFrameImpl(Function* function)
    : function_(function) {}

bool StackFrameImpl::isParameterOffset(int offset) const {
    return offset >= 0 && offset < parameterSize_;
}

Variable* StackFrameImpl::getVariableContaining(int offset) {
    auto it = variables_.lower_bound(offset);
    if (it != variables_.end() && it->first == offset)
        return it->second.get();
    if (it != variables_.begin()) {
        --it;
        int varOffset = it->first;
        int varLen = it->second->getLength();
        if (offset >= varOffset && offset < varOffset + varLen)
            return it->second.get();
    }
    return nullptr;
}

Variable* StackFrameImpl::createVariable(const std::string& name, int offset,
                                          DataType* dataType, SourceType source) {
    clearVariable(offset);
    auto var = std::make_unique<VariableImpl>(name, dataType, offset,
                                               function_->getProgram(), source);
    Variable* raw = var.get();
    variables_[offset] = std::move(var);
    return raw;
}

void StackFrameImpl::clearVariable(int offset) {
    variables_.erase(offset);
}

std::vector<Variable*> StackFrameImpl::getStackVariables() {
    std::vector<Variable*> result;
    for (auto& [offset, var] : variables_) {
        result.push_back(var.get());
    }
    return result;
}

std::vector<Variable*> StackFrameImpl::getParameters() {
    std::vector<Variable*> result;
    for (auto& [offset, var] : variables_) {
        if (offset >= 0)
            result.push_back(var.get());
    }
    return result;
}

std::vector<Variable*> StackFrameImpl::getLocals() {
    std::vector<Variable*> result;
    for (auto& [offset, var] : variables_) {
        if (offset < 0)
            result.push_back(var.get());
    }
    return result;
}

} // namespace ghidra
