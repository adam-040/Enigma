#pragma once

#include <ghidra/Variable.h>
#include <cstdint>

namespace ghidra {

class StackVariableComparator {
public:
    int compare(const Variable* var1, const Variable* var2) const;
    int compare(int offset1, const Variable* var2) const;
    int compare(const Variable* var1, int offset2) const;

    static StackVariableComparator* get();

    bool operator()(const Variable* var1, const Variable* var2) const {
        return compare(var1, var2) < 0;
    }

private:
    static int64_t getStackOffset(const Variable* var);
};

} // namespace ghidra
