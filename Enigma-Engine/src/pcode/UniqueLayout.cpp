#include <ghidra/UniqueLayout.h>
#include <ghidra/SleighLanguage.h>

namespace ghidra {

long UniqueLayout::getOffset(Type type, SleighLanguage* lang) {
    return 0x1000;
}

} // namespace ghidra
