#include <ghidra/TypeDatabase.h>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class MacOSTypeDatabase : public TypeDatabase {
public:
    bool getFunctionType(const std::string& funcName,
                         std::string& returnType,
                         std::vector<std::string>& paramTypes) const override {
        return false;
    }

    bool isNoReturn(const std::string& funcName) const override {
        return funcName == "abort" || funcName == "exit" || funcName == "_exit" ||
               funcName == "quick_exit" || funcName == "longjmp";
    }

    std::string getPlatformName() const override {
        return "MacOS";
    }
};

std::unique_ptr<TypeDatabase> createMacOSTypeDatabase() {
    return std::make_unique<MacOSTypeDatabase>();
}

} // namespace ghidra
