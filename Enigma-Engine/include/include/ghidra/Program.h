/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Program.h
/// \brief Main program interface - stores all information about a single program
/// Translated from: ghidra.program.model.listing.Program
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Language.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/Namespace.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Register.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/UniversalID.h>
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace ghidra {

class DataTypeManager;
class ReferenceManager;
class BookmarkManager;
class EquateTable;
class ExternalManager;
class ProgramUserData;
class RelocationTable;
class SourceFileManager;
class PropertyMapManager;
class AddressSetPropertyMap;
class IntRangeMap;
class TreeManager;
class FunctionTagManager;

class Program {
public:
    virtual FunctionTagManager* getFunctionTagManager() const { return nullptr; }
    static constexpr int MAX_OPERANDS = 16;
    static constexpr const char* ANALYSIS_PROPERTIES = "Analyzers";
    static constexpr const char* DISASSEMBLER_PROPERTIES = "Disassembler";
    static constexpr const char* PROGRAM_INFO = "Program Information";
    static constexpr const char* ANALYZED_OPTION_NAME = "Analyzed";
    static constexpr const char* ASK_TO_ANALYZE_OPTION_NAME = "Should Ask To Analyze";
    static constexpr const char* DATE_CREATED = "Date Created";
    static constexpr const char* CREATED_WITH_GHIDRA_VERSION = "Created With Ghidra Version";

    Program();
    Program(const std::string& name, Language* language, CompilerSpec* compilerSpec);
    virtual ~Program() = default;

    virtual const std::string& getName() const { return name_; }
    void setName(const std::string& name) { name_ = name; }

    virtual Language* getLanguage() const { return language_; }
    void setLanguage(Language* lang) {
        language_ = lang;
        if (lang) addressFactory_ = lang->getAddressFactory();
    }

    virtual CompilerSpec* getCompilerSpec() const { return compilerSpec_; }
    void setCompilerSpec(CompilerSpec* spec) { compilerSpec_ = spec; }

    LanguageID getLanguageID() const {
        return language_ ? language_->getLanguageID() : LanguageID("unknown");
    }

    virtual AddressFactory* getAddressFactory() const { return addressFactory_; }

    virtual Listing* getListing() const { return listing_.get(); }
    void setListing(std::unique_ptr<Listing> listing) { listing_ = std::move(listing); }

    virtual Memory* getMemory() const { return memory_.get(); }
    void setMemory(std::unique_ptr<Memory> mem) { memory_ = std::move(mem); }

    virtual SymbolTable* getSymbolTable() const { return symbolTable_.get(); }
    void setSymbolTable(std::unique_ptr<SymbolTable> table) { symbolTable_ = std::move(table); }

    virtual FunctionManager* getFunctionManager() const { return functionManager_.get(); }
    void setFunctionManager(std::unique_ptr<FunctionManager> mgr) { functionManager_ = std::move(mgr); }

    virtual DataTypeManager* getDataTypeManager() const { return dataTypeManager_; }
    void setDataTypeManager(DataTypeManager* mgr) { dataTypeManager_ = mgr; }

    virtual ReferenceManager* getReferenceManager() const { return referenceManager_; }
    void setReferenceManager(ReferenceManager* mgr) { referenceManager_ = mgr; }

    virtual BookmarkManager* getBookmarkManager() const { return bookmarkManager_; }
    void setBookmarkManager(BookmarkManager* mgr) { bookmarkManager_ = mgr; }

    virtual EquateTable* getEquateTable() const { return equateTable_; }
    void setEquateTable(EquateTable* table) { equateTable_ = table; }

    virtual ExternalManager* getExternalManager() const { return externalManager_; }
    void setExternalManager(ExternalManager* mgr) { externalManager_ = mgr; }

    ProgramUserData* getProgramUserData() const { return programUserData_; }
    void setProgramUserData(ProgramUserData* data) { programUserData_ = data; }

    virtual SourceFileManager* getSourceFileManager() const { return sourceFileManager_; }
    void setSourceFileManager(SourceFileManager* mgr) { sourceFileManager_ = mgr; }

    virtual RelocationTable* getRelocationTable() const { return relocationTable_; }
    void setRelocationTable(RelocationTable* table) { relocationTable_ = table; }

    virtual ProgramContext* getProgramContext() const { return programContext_; }
    void setProgramContext(ProgramContext* ctx) { programContext_ = ctx; }

    virtual PropertyMapManager* getUsrPropertyManager() const { return propertyManager_; }
    void setUsrPropertyManager(PropertyMapManager* mgr) { propertyManager_ = mgr; }

    virtual TreeManager* getTreeManager() const { return nullptr; }

    virtual Namespace* getGlobalNamespace() const { return globalNamespace_.get(); }

    int getDefaultPointerSize() const;

    const std::string& getCompiler() const { return compiler_; }
    void setCompiler(const std::string& c) { compiler_ = c; }

    CategoryPath getPreferredRootNamespaceCategoryPath() const {
        return preferredRootCategory_;
    }
    void setPreferredRootNamespaceCategoryPath(const std::string& path) {
        preferredRootCategory_ = CategoryPath(path);
    }

    const std::string& getExecutablePath() const { return executablePath_; }
    void setExecutablePath(const std::string& path) { executablePath_ = path; }

    const std::string& getExecutableFormat() const { return executableFormat_; }
    void setExecutableFormat(const std::string& format) { executableFormat_ = format; }

    const std::string& getExecutableMD5() const { return executableMD5_; }
    void setExecutableMD5(const std::string& md5) { executableMD5_ = md5; }

    const std::string& getExecutableSHA256() const { return executableSHA256_; }
    void setExecutableSHA256(const std::string& sha256) { executableSHA256_ = sha256; }

    Address getImageBase() const { return imageBase_; }
    void setImageBase(Address base) { imageBase_ = base; }

    Address getMinAddress() const { return minAddress_; }
    void setMinAddress(Address addr) { minAddress_ = addr; }

    Address getMaxAddress() const { return maxAddress_; }
    void setMaxAddress(Address addr) { maxAddress_ = addr; }

    Register* getRegister(const std::string& name) const;
    Register* getRegister(Address addr) const;
    Register* getRegister(Address addr, int size) const;
    std::vector<Register*> getRegisters(Address addr) const;

    long getUniqueProgramID() const { return uniqueID_.getValue(); }

    bool isAnalyzed() const { return isAnalyzed_; }
    void setAnalyzed(bool analyzed) { isAnalyzed_ = analyzed; }

    bool shouldAskToAnalyze() const { return askToAnalyze_; }
    void setAskToAnalyze(bool ask) { askToAnalyze_ = ask; }

    std::string toString() const;

private:
    std::string name_;
    Language* language_ = nullptr;
    CompilerSpec* compilerSpec_ = nullptr;
    AddressFactory* addressFactory_ = nullptr;
    std::unique_ptr<Listing> listing_;
    std::unique_ptr<Memory> memory_;
    std::unique_ptr<SymbolTable> symbolTable_;
    std::unique_ptr<FunctionManager> functionManager_;
    DataTypeManager* dataTypeManager_ = nullptr;
    ReferenceManager* referenceManager_ = nullptr;
    BookmarkManager* bookmarkManager_ = nullptr;
    EquateTable* equateTable_ = nullptr;
    ExternalManager* externalManager_ = nullptr;
    ProgramUserData* programUserData_ = nullptr;
    SourceFileManager* sourceFileManager_ = nullptr;
    RelocationTable* relocationTable_ = nullptr;
    ProgramContext* programContext_ = nullptr;
    PropertyMapManager* propertyManager_ = nullptr;
    std::unique_ptr<Namespace> globalNamespace_;
    std::string compiler_;
    CategoryPath preferredRootCategory_;
    std::string executablePath_;
    std::string executableFormat_;
    std::string executableMD5_;
    std::string executableSHA256_;
    Address imageBase_;
    Address minAddress_;
    Address maxAddress_;
    UniversalID uniqueID_;
    bool isAnalyzed_ = false;
    bool askToAnalyze_ = true;
};

} // namespace ghidra
