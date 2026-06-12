/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramDB.h
/// \brief In-memory program implementation (DB-ready structure)
/// Translated from: ghidra.program.database.ProgramDB
#pragma once

#include <ghidra/Program.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/ProgramChangeSet.h>
#include <ghidra/ProgramContextImpl.h>
#include <ghidra/ManagerDB.h>
#include <ghidra/AddressMap.h>
#include <ghidra/Listing.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/EquateTable.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/SourceFileManager.h>
#include <ghidra/PropertyMapManager.h>
#include <ghidra/TreeManager.h>
#include <ghidra/Memory.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/FunctionTagManager.h>
#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace ghidra {

class ProgramDB : public Program {
public:
    static constexpr int DB_VERSION = 33;
    static constexpr int NUM_UNDOS = 100;
    static constexpr const char* CONTENT_TYPE = "Program";

    static constexpr int MEMORY_MGR = 0;
    static constexpr int CODE_MGR = 1;
    static constexpr int SYMBOL_MGR = 2;
    static constexpr int NAMESPACE_MGR = 3;
    static constexpr int FUNCTION_MGR = 4;
    static constexpr int EXTERNAL_MGR = 5;
    static constexpr int REF_MGR = 6;
    static constexpr int DATA_MGR = 7;
    static constexpr int EQUATE_MGR = 8;
    static constexpr int BOOKMARK_MGR = 9;
    static constexpr int CONTEXT_MGR = 10;
    static constexpr int PROPERTY_MGR = 11;
    static constexpr int TREE_MGR = 12;
    static constexpr int RELOC_MGR = 13;
    static constexpr int SOURCE_FILE_MGR = 14;
    static constexpr int FUNCTION_TAG_MGR = 15;
    static constexpr int NUM_MANAGERS = 16;

    ProgramDB() = default;
    ProgramDB(const std::string& name, Language* language, CompilerSpec* compilerSpec)
        : Program(name, language, compilerSpec) {
        initialize(name, language, compilerSpec);
    }
    ~ProgramDB() override;

    void initialize(const std::string& name, Language* language, CompilerSpec* compilerSpec);

    int getDBVersion() const { return DB_VERSION; }
    const std::string& getName() const override { return name_; }
    void setName(const std::string& name) {
        Program::setName(name);
        name_ = name;
    }

    Language* getLanguage() const override { return language_; }
    void setLanguage(Language* lang) {
        Program::setLanguage(lang);
        language_ = lang;
        if (lang) {
            languageID_ = lang->getLanguageID();
            languageVersion_ = lang->getVersion();
            languageMinorVersion_ = lang->getMinorVersion();
        }
    }

    CompilerSpec* getCompilerSpec() const override { return compilerSpec_; }
    void setCompilerSpec(CompilerSpec* spec) {
        Program::setCompilerSpec(spec);
        compilerSpec_ = spec;
        if (spec) compilerSpecID_ = spec->getCompilerSpecID();
    }

    LanguageID getLanguageID() const { return languageID_; }
    void setLanguageID(const LanguageID& id) { languageID_ = id; }
    CompilerSpecID getCompilerSpecID() const { return compilerSpecID_; }
    void setCompilerSpecID(const CompilerSpecID& id) { compilerSpecID_ = id; }
    int getLanguageVersion() const { return languageVersion_; }
    int getLanguageMinorVersion() const { return languageMinorVersion_; }

    AddressFactory* getAddressFactory() const override { return addressFactory_.get(); }

    Listing* getListing() const override { return listing_.get(); }

    Memory* getMemory() const override { return memory_.get(); }
    void setMemory(Memory* mem) { memory_.reset(mem); }

    SymbolTable* getSymbolTable() const override { return symbolTable_.get(); }

    FunctionManager* getFunctionManager() const override { return functionManager_.get(); }

    DataTypeManager* getDataTypeManager() const override { return dataTypeManager_; }
    void setDataTypeManager(DataTypeManager* mgr) { dataTypeManager_ = mgr; }

    ReferenceManager* getReferenceManager() const override { return referenceManager_; }
    void setReferenceManager(ReferenceManager* mgr) { referenceManager_ = mgr; }

    BookmarkManager* getBookmarkManager() const override { return bookmarkManager_; }
    void setBookmarkManager(BookmarkManager* mgr) { bookmarkManager_ = mgr; }

    EquateTable* getEquateTable() const override { return equateTable_; }
    void setEquateTable(EquateTable* table) { equateTable_ = table; }

    ExternalManager* getExternalManager() const override { return externalManager_; }
    void setExternalManager(ExternalManager* mgr) { externalManager_ = mgr; }

    RelocationTable* getRelocationTable() const override { return relocationTable_; }
    void setRelocationTable(RelocationTable* table) { relocationTable_ = table; }

    SourceFileManager* getSourceFileManager() const override { return sourceFileManager_; }
    void setSourceFileManager(SourceFileManager* mgr) { sourceFileManager_ = mgr; }

    ProgramContext* getProgramContext() const override { return programContext_.get(); }

    PropertyMapManager* getUsrPropertyManager() const override { return propertyManager_; }
    void setUsrPropertyManager(PropertyMapManager* mgr) { propertyManager_ = mgr; }

    TreeManager* getTreeManager() const override { return treeManager_; }
    FunctionTagManager* getFunctionTagManager() const override { return functionTagManager_; }
    void setFunctionTagManager(FunctionTagManager* mgr) { functionTagManager_ = mgr; }

    AddressMap* getAddressMap() const { return addressMap_.get(); }

    ProgramChangeSet* getChangeSet() const { return changeSet_.get(); }

    Namespace* getGlobalNamespace() const override { return globalNamespace_.get(); }

    Register* getContextRegister() const { return contextRegister_; }

    Address getImageBase() const { return imageBase_; }
    void setImageBase(Address base) { imageBase_ = base; }

    Address getMinAddress() const { return minAddress_; }
    void setMinAddress(Address addr) { minAddress_ = addr; }

    Address getMaxAddress() const { return maxAddress_; }
    void setMaxAddress(Address addr) { maxAddress_ = addr; }

    bool isChangeable() const { return changeable_; }
    void setChangeable(bool c) { changeable_ = c; }

    bool isImageBaseOverride() const { return imageBaseOverride_; }
    void setImageBaseOverride(bool v) { imageBaseOverride_ = v; }

    Address getEffectiveImageBase() const { return effectiveImageBase_; }
    void setEffectiveImageBase(Address base) { effectiveImageBase_ = base; }

    long getUniqueProgramID() const { return uniqueID_.getValue(); }

    std::string toString() const;

private:
    std::string name_;
    Language* language_ = nullptr;
    CompilerSpec* compilerSpec_ = nullptr;
    LanguageID languageID_;
    CompilerSpecID compilerSpecID_;
    int languageVersion_ = 0;
    int languageMinorVersion_ = 0;
    std::unique_ptr<ProgramAddressFactory> addressFactory_;
    std::unique_ptr<AddressMap> addressMap_;
    std::unique_ptr<Listing> listing_;
    std::unique_ptr<Memory> memory_;
    std::unique_ptr<SymbolTable> symbolTable_;
    std::unique_ptr<FunctionManager> functionManager_;
    DataTypeManager* dataTypeManager_ = nullptr;
    ReferenceManager* referenceManager_ = nullptr;
    BookmarkManager* bookmarkManager_ = nullptr;
    EquateTable* equateTable_ = nullptr;
    ExternalManager* externalManager_ = nullptr;
    RelocationTable* relocationTable_ = nullptr;
    SourceFileManager* sourceFileManager_ = nullptr;
    std::unique_ptr<ProgramContextImpl> programContext_;
    PropertyMapManager* propertyManager_ = nullptr;
    TreeManager* treeManager_ = nullptr;
    FunctionTagManager* functionTagManager_ = nullptr;
    std::unique_ptr<ProgramChangeSet> changeSet_;
    std::unique_ptr<Namespace> globalNamespace_;
    Register* contextRegister_ = nullptr;
    Address imageBase_;
    Address minAddress_;
    Address maxAddress_;
    Address effectiveImageBase_;
    UniversalID uniqueID_;
    bool changeable_ = true;
    bool imageBaseOverride_ = false;
    bool languageUpgradeRequired_ = false;

    std::unique_ptr<DataTypeManager> dataTypeManagerImpl_;
    std::unique_ptr<ReferenceManager> referenceManagerImpl_;
    std::unique_ptr<BookmarkManager> bookmarkManagerImpl_;
    std::unique_ptr<EquateTable> equateTableImpl_;
    std::unique_ptr<ExternalManager> externalManagerImpl_;
    std::unique_ptr<RelocationTable> relocationTableImpl_;
    std::unique_ptr<SourceFileManager> sourceFileManagerImpl_;
    std::unique_ptr<PropertyMapManager> propertyManagerImpl_;
    std::unique_ptr<TreeManager> treeManagerImpl_;
    std::unique_ptr<FunctionTagManager> functionTagManagerImpl_;
};

} // namespace ghidra
