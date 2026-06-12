/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeWriter.h
/// \brief Emits ANSI-C declarations for DataType objects to an ostream.
/// Translated from: ghidra.program.model.data.DataTypeWriter
#pragma once

#include <iosfwd>
#include <set>
#include <string>
#include <vector>
#include <ghidra/DataTypeManager.h>

namespace ghidra {

class DataType;
class Composite;
class Structure;
class Union;
class Enum;
class Pointer;
class Array;
class TypeDef;
class FunctionDefinition;
class BitFieldDataType;
class Dynamic;
class TaskMonitor;

/// Emits C declarations for DataType objects to a std::ostream.
/// The output is valid ANSI-C and references are forward-declared where
/// needed to break cycles.
class DataTypeWriter {
public:
    static const std::string EOL;

    /// Construct a DataTypeWriter that writes C declarations to \p out.
    /// \p dtm may be null (uses the default data organization for size queries).
    /// \p cppStyleComments selects "// ..." vs "/* ... */" annotations.
    DataTypeWriter(DataTypeManager* dtm, std::ostream& out, bool cppStyleComments = false);

    /// Emit a C declaration for a single data type. The type and any
    /// composite / enum / typedef / function-pointer types it references
    /// are emitted in dependency order.
    void write(DataType* dt, TaskMonitor* monitor = nullptr);

    /// Emit C declarations for a list of data types.
    void write(const std::vector<DataType*>& types, TaskMonitor* monitor = nullptr);

    /// True if this writer has already emitted a definition for the given
    /// (data-type-by-name) entry. Useful for callers that want to control
    /// duplicate detection.
    bool isResolved(const std::string& typeName) const;

    /// Number of distinct types already emitted (forward-declared or defined).
    size_t resolvedCount() const { return inProgress_.size(); }

private:
    std::ostream& out_;
    DataTypeManager* dtm_;
    bool cppStyleComments_;

    // Types we have decided to handle (forward-declared or fully emitted).
    // Used to break recursion: doWrite() on an in-progress type is a no-op.
    std::set<std::string> inProgress_;
    // Types that have had their full C definition emitted.
    std::set<std::string> defined_;
    // Forward declarations already emitted (so we don't emit twice).
    std::set<std::string> forwardDeclared_;
    // Composite types that have been forward-declared and still need
    // their full definition emitted.
    std::vector<Composite*> pendingComposites_;
    // Enums that still need their full definition emitted.
    std::vector<Enum*> pendingEnums_;
    // Typedefs that still need their full definition emitted.
    std::vector<TypeDef*> pendingTypedefs_;

    std::string comment(const std::string& text) const;

    void writeBuiltInDecl(const std::string& name);
    void doWrite(DataType* dt, TaskMonitor* monitor);
    void writeCompositePreDeclaration(Composite* c);
    void writeStruct(Structure* s);
    void writeUnion(Union* u);
    void writeEnumPreDeclaration(Enum* e);
    void writeEnum(Enum* e);
    void writeTypedef(TypeDef* td);
    void writePointer(Pointer* p);
    void writeArray(Array* a);
    void writeFunctionDef(FunctionDefinition* fd);
    void writeBitField(BitFieldDataType* bf);
    void writeDynamic(Dynamic* d);

    void emitPending();

    static std::string getBaseTypeName(DataType* dt);
    static int getPointerDepth(Pointer* p);
    static std::string escapeName(const std::string& name);
};

} // namespace ghidra
