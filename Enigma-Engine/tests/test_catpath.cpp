#include <ghidra/StructureDataType.h>
#include <ghidra/CategoryPath.h>
#include <iostream>
int main() {
    using namespace ghidra;
    StructureDataType s("Foo", 0);
    std::cout << "before: " << s.getCategoryPath().getPath() << "\n";
    s.setCategoryPath(CategoryPath("/a"));
    std::cout << "after: " << s.getCategoryPath().getPath() << "\n";
    return 0;
}
