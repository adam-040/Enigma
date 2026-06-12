/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PcodeDataTypeManager.h
/// \brief Marshals DataType objects to and from the decompiler.
/// Translated from: ghidra.program.model.pcode.PcodeDataTypeManager
///
/// The Java original is ~1400 lines and tightly coupled to a full
/// Program/DataTypeManager/CompilerSpec/DecompilerLanguage/XML stack.
/// For the in-memory native pipeline (EnigmaPipeline) we only need:
///   - the metatype constants used by protorules,
///   - the static getMetatype(DataType*) helper (re-exported from
///     Metatype), and
///   - a pointer-stable instance object that PcodeFactory can return
///     from getDataTypeManager().
/// The full XML marshaling, BuiltInDataTypeManager enumeration, and
/// pointer-sized type emission are deferred until the upstream
/// dependencies (Program, CompilerSpec, etc.) are ported.
#pragma once

#include <ghidra/Metatype.h>
#include <string>

namespace ghidra {

class DataType;
class Program;
class NameTransformer;
class Encoder;

/// Mirrors ghidra.program.model.pcode.PcodeDataTypeManager in its
/// public surface. The instance methods that depend on a full Program
/// are stubbed (return null/empty/throw) until the upstream
/// infrastructure is ported; the static metatype helpers and
/// constants are the production-ready subset.
class PcodeDataTypeManager {
public:
    // Metatype constants. Values match Java PcodeDataTypeManager.java
    // (lines 56-68). These are independent of the values used by the
    // protorule helper struct ghidra::Metatype; both layers exist in
    // the C++ port because the Java metatype values for the marshaled
    // XML stream are part of the on-disk format and cannot be changed.
    static constexpr int TYPE_VOID    = 14;  // Standard "void" type
    static constexpr int TYPE_UNKNOWN = 12;  // Unknown low-level type
    static constexpr int TYPE_INT     = 11;  // Signed integer
    static constexpr int TYPE_UINT    = 10;  // Unsigned integer
    static constexpr int TYPE_BOOL    = 9;   // Boolean
    static constexpr int TYPE_CODE    = 8;   // Actual executable code
    static constexpr int TYPE_FLOAT   = 7;   // Floating-point
    static constexpr int TYPE_PTR     = 6;   // Pointer data-type
    static constexpr int TYPE_PTRREL  = 5;   // Pointer relative to base
    static constexpr int TYPE_ARRAY   = 4;   // Array data-type
    static constexpr int TYPE_STRUCT  = 3;   // Structure data-type
    static constexpr int TYPE_UNION   = 2;   // Union of data-types

    // ----- static helpers (re-exported from Metatype) -----

    /// Get the decompiler meta-type for a DataType.
    static int getMetatype(DataType* tp) { return Metatype::getMetatype(tp); }

    /// Convert a decompiler metatype code to its XML marshaling string.
    /// Returns "unknown" for unknown codes (does not throw, to match
    /// the C++ port's "best-effort" behavior; the Java version throws).
    static std::string getMetatypeString(int meta) {
        switch (meta) {
            case TYPE_VOID:    return "void";
            case TYPE_UNKNOWN: return "unknown";
            case TYPE_INT:     return "int";
            case TYPE_UINT:    return "uint";
            case TYPE_BOOL:    return "bool";
            case TYPE_CODE:    return "code";
            case TYPE_FLOAT:   return "float";
            case TYPE_PTR:     return "ptr";
            case TYPE_PTRREL:  return "ptrrel";
            case TYPE_ARRAY:   return "array";
            case TYPE_STRUCT:  return "struct";
            case TYPE_UNION:   return "union";
            default:           return "unknown";
        }
    }

    /// Convert a marshaling string to a metatype code. Returns
    /// TYPE_UNKNOWN for unrecognized strings (does not throw).
    static int getMetatypeFromString(const std::string& s) {
        if (s == "void")    return TYPE_VOID;
        if (s == "unknown") return TYPE_UNKNOWN;
        if (s == "int")     return TYPE_INT;
        if (s == "uint")    return TYPE_UINT;
        if (s == "bool")    return TYPE_BOOL;
        if (s == "code")    return TYPE_CODE;
        if (s == "float")   return TYPE_FLOAT;
        if (s == "ptr")     return TYPE_PTR;
        if (s == "ptrrel")  return TYPE_PTRREL;
        if (s == "array")   return TYPE_ARRAY;
        if (s == "struct")  return TYPE_STRUCT;
        if (s == "union")   return TYPE_UNION;
        return TYPE_UNKNOWN;
    }

    // ----- instance methods (stubbed; full impl deferred) -----

    /// Construct a PcodeDataTypeManager bound to a Program.
    /// The full Java version parses the Program's data-type manager
    /// and compiler spec; in the C++ port this is a no-op until those
    /// are ported.
    explicit PcodeDataTypeManager(Program* prog = nullptr) : program_(prog) {}

    virtual ~PcodeDataTypeManager() = default;

    /// @return the Program this manager is bound to, or nullptr.
    Program* getProgram() const { return program_; }

    /// @return the name transformer (currently always nullptr).
    NameTransformer* getNameTransformer() const { return nullptr; }

    /// Set the name transformer. Stub: the Java version rebinds the
    /// decompiler-name transformer used during DataType marshaling.
    void setNameTransformer(NameTransformer* /*t*/) {}

    /// Find a base/built-in data-type with the given name and id.
    /// @return nullptr in the stub; the full impl requires the
    /// program-side DataTypeManager.
    DataType* findBaseType(const std::string& /*name*/, long /*id*/) {
        return nullptr;
    }

    /// Find a non-builtin data-type by its temporary id.
    /// @return nullptr in the stub.
    DataType* findDataType(long /*id*/) { return nullptr; }

    /// Resolve a DataType object from a (name, id) pair.
    /// @return nullptr in the stub.
    DataType* resolveDataType(const std::string& /*name*/, long /*id*/) {
        return nullptr;
    }

    /// Encode the core built-in data-type list. Stub: does nothing.
    void encodeCoreTypes(Encoder& /*encoder*/) const {}

    /// Encode a data-type definition. Stub: does nothing.
    void encodeTypeDef(DataType* /*dt*/, Encoder& /*encoder*/, bool /*isTypedef*/) const {}

    /// @return the word-size (in bytes) used for pointer data-types.
    /// Returns 0 in the stub; the full impl queries the language.
    int getPointerWordSize() const { return 0; }

private:
    Program* program_;
};

} // namespace ghidra
