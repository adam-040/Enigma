#pragma once

#include <ghidra/Variable.h>
#include <ghidra/Parameter.h>

namespace ghidra {

class VariableFilter {
public:
    virtual ~VariableFilter() = default;
    virtual bool matches(Variable* variable) = 0;

    static VariableFilter* PARAMETER_FILTER();
    static VariableFilter* NONAUTO_PARAMETER_FILTER();
    static VariableFilter* LOCAL_VARIABLE_FILTER();
    static VariableFilter* STACK_VARIABLE_FILTER();
    static VariableFilter* COMPOUND_STACK_VARIABLE_FILTER();
    static VariableFilter* REGISTER_VARIABLE_FILTER();
    static VariableFilter* MEMORY_VARIABLE_FILTER();
    static VariableFilter* UNIQUE_VARIABLE_FILTER();
};

class ParameterFilter : public VariableFilter {
public:
    explicit ParameterFilter(bool allowAutoParams) : allowAutoParams_(allowAutoParams) {}
    bool matches(Variable* variable) override;
private:
    bool allowAutoParams_;
};

class LocalVariableFilter : public VariableFilter {
public:
    bool matches(Variable* variable) override;
};

class StackVariableFilter : public VariableFilter {
public:
    bool matches(Variable* variable) override;
};

class CompoundStackVariableFilter : public VariableFilter {
public:
    bool matches(Variable* variable) override;
};

class RegisterVariableFilter : public VariableFilter {
public:
    bool matches(Variable* variable) override;
};

class MemoryVariableFilter : public VariableFilter {
public:
    bool matches(Variable* variable) override;
};

class UniqueVariableFilter : public VariableFilter {
public:
    bool matches(Variable* variable) override;
};

} // namespace ghidra
