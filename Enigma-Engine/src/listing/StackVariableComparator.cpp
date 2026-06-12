#include <ghidra/StackVariableComparator.h>
#include <ghidra/VariableStorage.h>

namespace ghidra {

int StackVariableComparator::compare(const Variable* var1, const Variable* var2) const {
    int64_t offset1 = getStackOffset(var1);
    int64_t offset2 = getStackOffset(var2);
    if (offset1 < offset2) return -1;
    if (offset2 < offset1) return 1;
    return 0;
}

int StackVariableComparator::compare(int offset1, const Variable* var2) const {
    int64_t offset2 = getStackOffset(var2);
    if (offset1 < offset2) return -1;
    if (offset2 < offset1) return 1;
    return 0;
}

int StackVariableComparator::compare(const Variable* var1, int offset2) const {
    int64_t offset1 = getStackOffset(var1);
    if (offset1 < offset2) return -1;
    if (offset2 < offset1) return 1;
    return 0;
}

int64_t StackVariableComparator::getStackOffset(const Variable* var) {
    if (var && var->hasStackStorage()) {
        return var->getLastStorageVarnode().getAddress().getOffset();
    }
    return 0;
}

StackVariableComparator* StackVariableComparator::get() {
    static StackVariableComparator inst;
    return &inst;
}

} // namespace ghidra
