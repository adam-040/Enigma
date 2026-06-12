/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramDB.cpp
/// \brief In-memory program implementation (DB-ready structure)
/// Translated from: ghidra.program.database.ProgramDB

#include <ghidra/ProgramDB.h>
#include <ghidra/VariableUtilities.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/ReferenceManagerImpl.h>
#include <ghidra/BookmarkManagerImpl.h>
#include <ghidra/EquateTableImpl.h>
#include <ghidra/ExternalManagerImpl.h>
#include <ghidra/RelocationTableImpl.h>
#include <ghidra/SourceFileManagerImpl.h>
#include <ghidra/PropertyMapManagerImpl.h>
#include <ghidra/TreeManager.h>
#include <ghidra/FunctionTagManagerImpl.h>
#include <ghidra/AddressMapImpl.h>

namespace ghidra {

void ProgramDB::initialize(const std::string& name, Language* language, CompilerSpec* compilerSpec) {
    name_ = name;
    language_ = language;
    compilerSpec_ = compilerSpec;
    languageID_ = language ? language->getLanguageID() : LanguageID("unknown");
    compilerSpecID_ = compilerSpec ? compilerSpec->getCompilerSpecID() : CompilerSpecID();
    languageVersion_ = language ? language->getVersion() : 0;
    languageMinorVersion_ = language ? language->getMinorVersion() : 0;

    addressFactory_ = std::make_unique<ProgramAddressFactory>(language, compilerSpec);

    if (language) {
        auto* af = language->getAddressFactory();
        if (af) {
            for (auto* space : af->getAddressSpaces()) {
                addressFactory_->addAddressSpace(const_cast<AddressSpace*>(space));
                if (space->getType() == AddressSpace::TYPE_RAM && !addressFactory_->getDefaultAddressSpace()) {
                    addressFactory_->setDefaultSpace(const_cast<AddressSpace*>(space));
                }
            }
        }
        if (auto* pc = language->getProgramCounter()) {
            contextRegister_ = pc;
        }
    }

    programContext_ = std::make_unique<ProgramContextImpl>(contextRegister_);
    symbolTable_ = std::make_unique<SymbolTable>(this);
    functionManager_ = std::make_unique<FunctionManager>(this);
    listing_ = std::make_unique<Listing>(this);
    memory_ = std::make_unique<DefaultMemory>(addressFactory_.get());
    addressMap_ = std::make_unique<AddressMapImpl>(0, addressFactory_.get());
    changeSet_ = std::make_unique<ProgramChangeSet>(addressMap_.get(), NUM_UNDOS);

    globalNamespace_ = std::make_unique<Namespace>("global", nullptr, Namespace::GLOBAL_NAMESPACE_ID);

    referenceManagerImpl_ = std::make_unique<ReferenceManagerImpl>(this);
    referenceManager_ = referenceManagerImpl_.get();

    bookmarkManagerImpl_ = std::make_unique<BookmarkManagerImpl>(this);
    bookmarkManager_ = bookmarkManagerImpl_.get();

    equateTableImpl_ = std::make_unique<EquateTableImpl>();
    equateTable_ = equateTableImpl_.get();

    externalManagerImpl_ = std::make_unique<ExternalManagerImpl>();
    externalManager_ = externalManagerImpl_.get();

    relocationTableImpl_ = std::make_unique<RelocationTableImpl>();
    relocationTable_ = relocationTableImpl_.get();

    sourceFileManagerImpl_ = std::make_unique<SourceFileManagerImpl>();
    sourceFileManager_ = sourceFileManagerImpl_.get();

    propertyManagerImpl_ = std::make_unique<PropertyMapManagerImpl>();
    propertyManager_ = propertyManagerImpl_.get();

    treeManagerImpl_ = std::make_unique<TreeManager>(this);
    treeManager_ = treeManagerImpl_.get();

    functionTagManagerImpl_ = std::make_unique<FunctionTagManagerImpl>(this);
    functionTagManager_ = functionTagManagerImpl_.get();

    dataTypeManagerImpl_ = std::make_unique<DataTypeManagerImpl>(name);
    dataTypeManager_ = dataTypeManagerImpl_.get();
    VariableUtilities::registerDtmToProgram(dataTypeManager_, this);
}

ProgramDB::~ProgramDB() {
    if (dataTypeManager_) {
        VariableUtilities::unregisterDtmToProgram(dataTypeManager_);
    }
}

std::string ProgramDB::toString() const {
    return name_ + " (DB v" + std::to_string(DB_VERSION) + ")";
}

} // namespace ghidra
