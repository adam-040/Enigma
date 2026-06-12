#pragma once

#include <ghidra/Processor.h>
#include <ghidra/Endian.h>
#include <ghidra/LanguageID.h>
#include <ghidra/CompilerSpecDescription.h>
#include <string>
#include <vector>
#include <map>

namespace ghidra {

class LanguageDescription {
public:
    virtual ~LanguageDescription() = default;
    virtual LanguageID getLanguageID() const = 0;
    virtual const std::string& getDescription() const = 0;
    virtual Processor getProcessor() const = 0;
    virtual Endian getEndian() const = 0;
    virtual Endian getInstructionEndian() const = 0;
    virtual int getSize() const = 0;
    virtual const std::string& getVariant() const = 0;
    virtual int getVersion() const = 0;
    virtual int getMinorVersion() const = 0;
    virtual bool isDeprecated() const = 0;
    virtual std::vector<CompilerSpecDescription> getCompilerSpecDescriptions() const = 0;
    virtual std::map<std::string, std::vector<std::string>> getExternalNames() const = 0;
};

} // namespace ghidra
