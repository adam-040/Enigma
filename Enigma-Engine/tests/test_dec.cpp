#include "ghidra/DataTypeUtilities.h"
#include <iostream>
int main() {
    using namespace ghidra;
    std::cout << "[" << getPointerArrayDecorations("int * *") << "]\n";
    std::cout << "[" << getPointerArrayDecorations("int *") << "]\n";
    std::cout << "[" << getPointerArrayDecorations("int") << "]\n";
    std::cout << "[" << getPointerArrayDecorations("int[10]") << "]\n";
    return 0;
}
