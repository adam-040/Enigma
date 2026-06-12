// NOTE: This is a standalone wrapper used only by test_compile.cpp and
// the native pipeline tool (enigma_decompile.cpp). The main decompilation
// tool (enigma_decompile_full.cpp) uses ghidra_decompiler::Architecture
// (from decompiler/architecture.hh) directly via SimpleBinaryArch.

#pragma once

#include <ghidra/AddrSpace.h>
#include <ghidra/LoadImage.h>
#include <ghidra/Translate.h>
#include <ghidra/Scope.h>
#include <ghidra/TypeFactory.h>
#include <ghidra/ContextDatabase.h>
#include <string>
#include <vector>
#include <ghidra/Types.h>
#include <map>

namespace ghidra {

class Sleigh;

class Architecture {
public:
    enum ArchitectureType {
        ARCH_SLEIGH,
        ARCH_RAW,
        ARCH_GHIDRA,
        ARCH_XML
    };

protected:
    std::string name;
    ArchitectureType type;
    bool initialized;
    bool m_bigEndian;
    int4 pointerSize;

    AddrSpaceManager spaceManager;
    TypeFactory typeFactory;
    LoadImage* loader;
    Translate* translate;
    ScopeInternal* globalScope;
    ContextDatabase contextDatabase;

    std::vector<std::string> warnings;
    std::vector<std::string> errors;

public:
    Architecture(const std::string& nm, ArchitectureType t);
    virtual ~Architecture();

    virtual bool initialize() = 0;
    bool isInitialized() const { return initialized; }

    const std::string& getName() const { return name; }
    ArchitectureType getType() const { return type; }
    bool isBigEndian() const { return m_bigEndian; }
    int4 getPointerSize() const { return pointerSize; }

    AddrSpaceManager& getSpaceManager() { return spaceManager; }
    const AddrSpaceManager& getSpaceManager() const { return spaceManager; }
    TypeFactory& getTypeFactory() { return typeFactory; }
    const TypeFactory& getTypeFactory() const { return typeFactory; }
    LoadImage* getLoader() const { return loader; }
    Translate* getTranslate() const { return translate; }
    ScopeInternal* getGlobalScope() const { return globalScope; }
    ContextDatabase& getContextDatabase() { return contextDatabase; }
    const ContextDatabase& getContextDatabase() const { return contextDatabase; }

    void setLoader(LoadImage* ld) { loader = ld; }
    void setTranslate(Translate* t) { translate = t; }
    void setBigEndian(bool val) { m_bigEndian = val; }
    void setPointerSize(int4 size) { pointerSize = size; }

    Address getDefaultCodeAddress(uintb offset) const;
    Address getConstantAddress(uintb val, int4 size) const;
    Address getUniqueAddress(uintb offset, int4 size) const;

    void addWarning(const std::string& msg) { warnings.push_back(msg); }
    void addError(const std::string& msg) { errors.push_back(msg); }
    const std::vector<std::string>& getWarnings() const { return warnings; }
    const std::vector<std::string>& getErrors() const { return errors; }
    bool hasErrors() const { return !errors.empty(); }
    bool hasWarnings() const { return !warnings.empty(); }
    void clearMessages() { warnings.clear(); errors.clear(); }

    virtual void saveXml(std::string& output) const;
    virtual void restoreXml(const std::string& input);
};

class ArchitectureSleigh : public Architecture {
private:
    std::string slaFile;
    Sleigh* sleighEngine;

public:
    ArchitectureSleigh(const std::string& nm, LoadImage* ld, const std::string& slaPath);
    ~ArchitectureSleigh() override;

    bool initialize() override;
    Sleigh* getSleigh() const { return sleighEngine; }
    const std::string& getSlaFile() const { return slaFile; }
};

class ArchitectureRaw : public Architecture {
public:
    ArchitectureRaw(const std::string& nm, LoadImage* ld, int4 ptrSize, bool endian);
    ~ArchitectureRaw() override;

    bool initialize() override;
};

} // namespace ghidra
