#pragma once

#include <ghidra/LanguageDescription.h>
#include <ghidra/LanguageID.h>
#include <ghidra/CompilerSpecID.h>
#include <ghidra/CompilerSpecNotFoundException.h>
#include <ghidra/Endian.h>
#include <ghidra/Processor.h>
#include <string>
#include <vector>
#include <map>
#include <sstream>

namespace ghidra {

class BasicLanguageDescription : public LanguageDescription {
public:
    BasicLanguageDescription(const LanguageID& id, Processor processor, Endian endian,
                             Endian instructionEndian, int size, const std::string& variant,
                             const std::string& description, int version, int minorVersion,
                             bool deprecated, const std::vector<CompilerSpecDescription>& compilerSpecs,
                             const std::map<std::string, std::vector<std::string>>& externalNames = {})
        : languageId_(id), processor_(processor), endian_(endian),
          instructionEndian_(instructionEndian), size_(size), variant_(variant),
          description_(description), version_(version), minorVersion_(minorVersion),
          deprecated_(deprecated), externalNames_(externalNames)
    {
        for (const auto& cs : compilerSpecs) {
            compatibleCompilerSpecs_[cs.getCompilerSpecID()] = cs;
        }
    }

    BasicLanguageDescription(const LanguageID& id, Processor processor, Endian endian,
                             Endian instructionEndian, int size, const std::string& variant,
                             const std::string& description, int version, int minorVersion,
                             bool deprecated, const CompilerSpecDescription& compilerSpec,
                             const std::map<std::string, std::vector<std::string>>& externalNames = {})
        : languageId_(id), processor_(processor), endian_(endian),
          instructionEndian_(instructionEndian), size_(size), variant_(variant),
          description_(description), version_(version), minorVersion_(minorVersion),
          deprecated_(deprecated), externalNames_(externalNames)
    {
        compatibleCompilerSpecs_[compilerSpec.getCompilerSpecID()] = compilerSpec;
    }

    LanguageID getLanguageID() const override { return languageId_; }
    const std::string& getDescription() const override { return description_; }
    Processor getProcessor() const override { return processor_; }
    Endian getEndian() const override { return endian_; }
    Endian getInstructionEndian() const override { return instructionEndian_; }
    int getSize() const override { return size_; }
    const std::string& getVariant() const override { return variant_; }
    int getVersion() const override { return version_; }
    int getMinorVersion() const override { return minorVersion_; }
    bool isDeprecated() const override { return deprecated_; }

    std::vector<CompilerSpecDescription> getCompilerSpecDescriptions() const override {
        std::vector<CompilerSpecDescription> result;
        result.reserve(compatibleCompilerSpecs_.size());
        for (const auto& pair : compatibleCompilerSpecs_) {
            result.push_back(pair.second);
        }
        return result;
    }

    std::vector<CompilerSpecDescription> getCompatibleCompilerSpecDescriptions() const {
        return getCompilerSpecDescriptions();
    }

    CompilerSpecDescription getCompilerSpecDescriptionByID(const CompilerSpecID& compilerSpecID) const {
        auto it = compatibleCompilerSpecs_.find(compilerSpecID);
        if (it == compatibleCompilerSpecs_.end()) {
            throw CompilerSpecNotFoundException(languageId_, compilerSpecID);
        }
        return it->second;
    }

    std::map<std::string, std::vector<std::string>> getExternalNames() const override {
        return externalNames_;
    }

    std::vector<std::string> getExternalNames(const std::string& key) const {
        auto it = externalNames_.find(key);
        if (it != externalNames_.end()) {
            return it->second;
        }
        return {};
    }

    std::size_t hashCode() const {
        return std::hash<std::string>{}(languageId_.getIdAsString());
    }

    bool equals(const LanguageDescription* other) const {
        if (!other) return false;
        return languageId_ == other->getLanguageID();
    }

    bool operator==(const BasicLanguageDescription& other) const {
        return languageId_ == other.languageId_;
    }

    bool operator!=(const BasicLanguageDescription& other) const {
        return languageId_ != other.languageId_;
    }

    std::string toString() const {
        std::ostringstream oss;
        oss << processor_.getName() << "/"
            << EndianUtil::toString(endian_) << "/"
            << size_ << "/" << variant_;
        return oss.str();
    }

private:
    LanguageID languageId_;
    Processor processor_;
    Endian endian_;
    Endian instructionEndian_;
    int size_;
    std::string variant_;
    std::string description_;
    int version_;
    int minorVersion_;
    bool deprecated_;
    std::map<CompilerSpecID, CompilerSpecDescription> compatibleCompilerSpecs_;
    std::map<std::string, std::vector<std::string>> externalNames_;
};

} // namespace ghidra
