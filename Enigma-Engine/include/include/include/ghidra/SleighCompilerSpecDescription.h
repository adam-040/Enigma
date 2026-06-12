#pragma once

#include <ghidra/BasicCompilerSpecDescription.h>
#include <string>

namespace ghidra {

class SleighCompilerSpecDescription : public BasicCompilerSpecDescription {
public:
    SleighCompilerSpecDescription(const CompilerSpecID& id, const std::string& name, const std::string& file)
        : BasicCompilerSpecDescription(id, name), file_(file) {}

    const std::string& getFile() const { return file_; }

private:
    std::string file_;
};

} // namespace ghidra
