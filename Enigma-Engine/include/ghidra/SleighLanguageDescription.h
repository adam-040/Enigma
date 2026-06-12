#pragma once

#include <ghidra/LanguageDescription.h>
#include <ghidra/LanguageID.h>
#include <ghidra/Endian.h>
#include <ghidra/Processor.h>
#include <string>
#include <vector>
#include <map>
#include <ghidra/SleighLanguageFile.h>
#include <set>
#include <stdexcept>

namespace ghidra {

class SleighLanguageDescription : public LanguageDescription {
public:
    SleighLanguageDescription() = default;
    SleighLanguageDescription(LanguageID id, const std::string& description,
                              Processor processor, Endian endian, Endian instructionEndian,
                              int size, const std::string& variant, int version, int minorVersion)
        : id_(id), description_(description), processor_(processor),
          endian_(endian), instructionEndian_(instructionEndian),
          size_(size), variant_(variant), version_(version),
          minorVersion_(minorVersion) {}

    LanguageID getLanguageID() const override { return id_; }
    const std::string& getDescription() const override { return description_; }
    Processor getProcessor() const override { return processor_; }
    Endian getEndian() const override { return endian_; }
    Endian getInstructionEndian() const override { return instructionEndian_; }
    int getSize() const override { return size_; }
    const std::string& getVariant() const override { return variant_; }
    int getVersion() const override { return version_; }
    int getMinorVersion() const override { return minorVersion_; }
    bool isDeprecated() const override { return deprecated_; }
    std::vector<CompilerSpecDescription> getCompilerSpecDescriptions() const override { return compilerSpecs_; }
    std::map<std::string, std::vector<std::string>> getExternalNames() const override { return externalNames_; }

    std::set<std::string> getTruncatedSpaceNames() const { return truncatedSpaces_; }
    int getTruncatedSpaceSize(const std::string& spaceName) const {
        auto it = truncatedSpaceMap_.find(spaceName);
        if (it == truncatedSpaceMap_.end()) throw std::runtime_error("Space not found");
        return it->second;
    }

    void setDeprecated(bool d) { deprecated_ = d; }

    void setDefsFile(const std::string& f) { defsFile_ = f; }
    void setSpecFile(const std::string& f) { specFile_ = f; }
    void setLanguageFile(const SleighLanguageFile& f) { languageFile_ = new SleighLanguageFile(f); }
    void setManualIndexFile(const std::string& f) { manualIndexFile_ = f; }

    const std::string& getDefsFile() const { return defsFile_; }
    const std::string& getSpecFile() const { return specFile_; }
    const SleighLanguageFile* getLanguageFile() const { return languageFile_; }
    const std::string& getManualIndexFile() const { return manualIndexFile_; }

    ~SleighLanguageDescription() { delete languageFile_; }

private:
    LanguageID id_;
    std::string description_;
    Processor processor_;
    Endian endian_;
    Endian instructionEndian_;
    int size_ = 32;
    std::string variant_;
    int version_ = 1;
    int minorVersion_ = 0;
    bool deprecated_ = false;
    std::vector<CompilerSpecDescription> compilerSpecs_;
    std::map<std::string, std::vector<std::string>> externalNames_;
    std::set<std::string> truncatedSpaces_;
    std::map<std::string, int> truncatedSpaceMap_;
    std::string defsFile_;
    std::string specFile_;
    SleighLanguageFile* languageFile_ = nullptr;
    std::string manualIndexFile_;
};

} // namespace ghidra
