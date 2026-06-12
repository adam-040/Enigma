#include <ghidra/VariableFilter.h>

namespace ghidra {

bool ParameterFilter::matches(Variable* variable) {
    auto* p = dynamic_cast<Parameter*>(variable);
    if (!p) return false;
    return !p->isAutoParameter() || allowAutoParams_;
}

bool LocalVariableFilter::matches(Variable* variable) {
    return dynamic_cast<Parameter*>(variable) == nullptr;
}

bool StackVariableFilter::matches(Variable* variable) {
    return variable->isStackVariable();
}

bool CompoundStackVariableFilter::matches(Variable* variable) {
    return variable->hasStackStorage();
}

bool RegisterVariableFilter::matches(Variable* variable) {
    return variable->isRegisterVariable();
}

bool MemoryVariableFilter::matches(Variable* variable) {
    return variable->isMemoryVariable();
}

bool UniqueVariableFilter::matches(Variable* variable) {
    return variable->isUniqueVariable();
}

static ParameterFilter PARAM_FILTER_ALLOW_AUTO(true);
static ParameterFilter PARAM_FILTER_NO_AUTO(false);
static LocalVariableFilter LOCAL_FILTER;
static StackVariableFilter STACK_FILTER;
static CompoundStackVariableFilter COMPOUND_STACK_FILTER;
static RegisterVariableFilter REGISTER_FILTER;
static MemoryVariableFilter MEMORY_FILTER;
static UniqueVariableFilter UNIQUE_FILTER;

VariableFilter* VariableFilter::PARAMETER_FILTER() { return &PARAM_FILTER_ALLOW_AUTO; }
VariableFilter* VariableFilter::NONAUTO_PARAMETER_FILTER() { return &PARAM_FILTER_NO_AUTO; }
VariableFilter* VariableFilter::LOCAL_VARIABLE_FILTER() { return &LOCAL_FILTER; }
VariableFilter* VariableFilter::STACK_VARIABLE_FILTER() { return &STACK_FILTER; }
VariableFilter* VariableFilter::COMPOUND_STACK_VARIABLE_FILTER() { return &COMPOUND_STACK_FILTER; }
VariableFilter* VariableFilter::REGISTER_VARIABLE_FILTER() { return &REGISTER_FILTER; }
VariableFilter* VariableFilter::MEMORY_VARIABLE_FILTER() { return &MEMORY_FILTER; }
VariableFilter* VariableFilter::UNIQUE_VARIABLE_FILTER() { return &UNIQUE_FILTER; }

} // namespace ghidra
