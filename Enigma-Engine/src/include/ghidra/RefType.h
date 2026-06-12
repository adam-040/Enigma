/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RefType.h
/// \brief Reference types and FlowTypes for instruction flow analysis
#pragma once

#include <cstdint>
#include <string>
#include <functional>

namespace ghidra {

/**
 * RefType defines reference types used to specify the nature of a directional
 * relationship between a source-location and a destination-location.
 * Translated from: ghidra.program.model.symbol.RefType (abstract class)
 *                + ghidra.program.model.symbol.FlowType
 *                + ghidra.program.model.symbol.DataRefType
 */
class RefType {
protected:
    int8_t type_;
    std::string name_;

    RefType(int8_t type, const std::string& name) : type_(type), name_(name) {}

public:
    virtual ~RefType() = default;

    int8_t getValue() const { return type_; }
    const std::string& getName() const { return name_; }
    const std::string& toString() const { return name_; }

    bool operator==(const RefType& other) const { return type_ == other.type_; }
    bool operator!=(const RefType& other) const { return type_ != other.type_; }
    std::size_t hash() const { return std::hash<int8_t>{}(type_); }

    // Data related methods (default: false, overridden by DataRefType)
    virtual bool isData() const { return false; }
    virtual bool isRead() const { return false; }
    virtual bool isWrite() const { return false; }

    // Flow related methods (default: false, overridden by FlowType)
    virtual bool isFlow() const { return false; }
    virtual bool isIndirect() const { return false; }
    virtual bool hasFallthrough() const { return false; }
    virtual bool isCall() const { return false; }
    virtual bool isJump() const { return false; }
    virtual bool isConditional() const { return false; }
    virtual bool isUnConditional() const { return !isConditional(); }
    virtual bool isComputed() const { return false; }
    virtual bool isTerminal() const { return false; }
    virtual bool isOverride() const { return false; }
    bool isFallthrough() const; // defined after FlowType/statics

    std::string getDisplayString() const;

    // Internal type constants
    static constexpr int8_t __INVALID = -2;
    static constexpr int8_t __UNKNOWNFLOW = -1;
    static constexpr int8_t __FALL_THROUGH = 0;
    static constexpr int8_t __UNCONDITIONAL_JUMP = 1;
    static constexpr int8_t __CONDITIONAL_JUMP = 2;
    static constexpr int8_t __UNCONDITIONAL_CALL = 3;
    static constexpr int8_t __CONDITIONAL_CALL = 4;
    static constexpr int8_t __TERMINATOR = 5;
    static constexpr int8_t __COMPUTED_JUMP = 6;
    static constexpr int8_t __CONDITIONAL_TERMINATOR = 7;
    static constexpr int8_t __COMPUTED_CALL = 8;
    static constexpr int8_t __INDIRECTION = 9;
    static constexpr int8_t __CALL_TERMINATOR = 10;
    static constexpr int8_t __JUMP_TERMINATOR = 11;
    static constexpr int8_t __CONDITIONAL_COMPUTED_JUMP = 12;
    static constexpr int8_t __CONDITIONAL_COMPUTED_CALL = 13;
    static constexpr int8_t __CONDITIONAL_CALL_TERMINATOR = 14;
    static constexpr int8_t __COMPUTED_CALL_TERMINATOR = 15;
    static constexpr int8_t __CALL_OVERRIDE_UNCONDITIONAL = 16;
    static constexpr int8_t __JUMP_OVERRIDE_UNCONDITIONAL = 17;
    static constexpr int8_t __CALLOTHER_OVERRIDE_CALL = 18;
    static constexpr int8_t __CALLOTHER_OVERRIDE_JUMP = 19;

    // Data reference type constants
    static constexpr int8_t __UNKNOWNDATA = 100;
    static constexpr int8_t __READ = 101;
    static constexpr int8_t __WRITE = 102;
    static constexpr int8_t __READ_WRITE = 103;
    static constexpr int8_t __READ_IND = 104;
    static constexpr int8_t __WRITE_IND = 105;
    static constexpr int8_t __READ_WRITE_IND = 106;
    static constexpr int8_t __UNKNOWNPARAM = 107;
    static constexpr int8_t __EXTERNAL_REF = 113;
    static constexpr int8_t __UNKNOWNDATA_IND = 114;
    static constexpr int8_t __DYNAMICDATA = 127;
};

/**
 * FlowType defines flow types for instructions.
 * Translated from: ghidra.program.model.symbol.FlowType
 */
class FlowType : public RefType {
private:
    bool hasFall_;
    bool isCall_;
    bool isJump_;
    bool isTerminal_;
    bool isConditional_;
    bool isComputed_;
    bool isOverride_;

public:
    FlowType(int8_t type, const std::string& name,
             bool hasFall, bool isCall, bool isJump,
             bool isTerminal, bool isConditional,
             bool isComputed, bool isOverride)
        : RefType(type, name),
          hasFall_(hasFall), isCall_(isCall), isJump_(isJump),
          isTerminal_(isTerminal), isConditional_(isConditional),
          isComputed_(isComputed), isOverride_(isOverride) {}

    bool isFlow() const override { return true; }
    bool hasFallthrough() const override { return hasFall_; }
    bool isCall() const override { return isCall_; }
    bool isJump() const override { return isJump_; }
    bool isTerminal() const override { return isTerminal_; }
    bool isConditional() const override { return isConditional_; }
    bool isUnConditional() const override { return !isConditional_; }
    bool isComputed() const override { return isComputed_; }
    bool isOverride() const override { return isOverride_; }
};

/**
 * DataRefType defines data reference types.
 * Translated from: ghidra.program.model.symbol.DataRefType
 */
class DataRefType : public RefType {
public:
    static constexpr int READX = 1;
    static constexpr int WRITEX = 2;
    static constexpr int INDX = 4;

private:
    int flags_;

public:
    DataRefType(int8_t type, const std::string& name, int flags)
        : RefType(type, name), flags_(flags) {}

    bool isData() const override { return true; }
    bool isRead() const override { return (flags_ & READX) != 0; }
    bool isWrite() const override { return (flags_ & WRITEX) != 0; }
    bool isIndirect() const override { return (flags_ & INDX) != 0; }
};

// ========== Static FlowType instances ==========
// These match the Java static final fields in RefType exactly

namespace RefTypes {

    // Flow types
    inline const FlowType INVALID{RefType::__INVALID, "INVALID", true, false, false, false, false, false, false};
    inline const FlowType FLOW{RefType::__UNKNOWNFLOW, "FLOW", true, false, false, false, false, false, false};
    inline const FlowType FALL_THROUGH{RefType::__FALL_THROUGH, "FALL_THROUGH", true, false, false, false, false, false, false};
    inline const FlowType UNCONDITIONAL_JUMP{RefType::__UNCONDITIONAL_JUMP, "UNCONDITIONAL_JUMP", false, false, true, false, false, false, false};
    inline const FlowType CONDITIONAL_JUMP{RefType::__CONDITIONAL_JUMP, "CONDITIONAL_JUMP", true, false, true, false, true, false, false};
    inline const FlowType UNCONDITIONAL_CALL{RefType::__UNCONDITIONAL_CALL, "UNCONDITIONAL_CALL", true, true, false, false, false, false, false};
    inline const FlowType CONDITIONAL_CALL{RefType::__CONDITIONAL_CALL, "CONDITIONAL_CALL", true, true, false, false, true, false, false};
    inline const FlowType TERMINATOR{RefType::__TERMINATOR, "TERMINATOR", false, false, false, true, false, false, false};
    inline const FlowType COMPUTED_JUMP{RefType::__COMPUTED_JUMP, "COMPUTED_JUMP", false, false, true, false, false, true, false};
    inline const FlowType CONDITIONAL_TERMINATOR{RefType::__CONDITIONAL_TERMINATOR, "CONDITIONAL_TERMINATOR", true, false, false, true, true, false, false};
    inline const FlowType COMPUTED_CALL{RefType::__COMPUTED_CALL, "COMPUTED_CALL", true, true, false, false, false, true, false};
    inline const FlowType CALL_TERMINATOR{RefType::__CALL_TERMINATOR, "CALL_TERMINATOR", false, true, false, true, false, false, false};
    inline const FlowType COMPUTED_CALL_TERMINATOR{RefType::__COMPUTED_CALL_TERMINATOR, "COMPUTED_CALL_TERMINATOR", false, true, false, true, false, true, false};
    inline const FlowType CONDITIONAL_CALL_TERMINATOR{RefType::__CONDITIONAL_CALL_TERMINATOR, "CONDITIONAL_CALL_TERMINATOR", false, true, false, true, true, false, false};
    inline const FlowType CONDITIONAL_COMPUTED_CALL{RefType::__CONDITIONAL_COMPUTED_CALL, "CONDITIONAL_COMPUTED_CALL", true, true, false, false, true, true, false};
    inline const FlowType CONDITIONAL_COMPUTED_JUMP{RefType::__CONDITIONAL_COMPUTED_JUMP, "CONDITIONAL_COMPUTED_JUMP", true, false, true, false, true, true, false};
    inline const FlowType JUMP_TERMINATOR{RefType::__JUMP_TERMINATOR, "JUMP_TERMINATOR", false, false, true, true, false, false, false};
    inline const FlowType INDIRECTION{RefType::__INDIRECTION, "INDIRECTION", false, false, false, false, false, false, false};
    inline const FlowType CALL_OVERRIDE_UNCONDITIONAL{RefType::__CALL_OVERRIDE_UNCONDITIONAL, "CALL_OVERRIDE_UNCONDITIONAL", true, true, false, false, false, false, true};
    inline const FlowType JUMP_OVERRIDE_UNCONDITIONAL{RefType::__JUMP_OVERRIDE_UNCONDITIONAL, "JUMP_OVERRIDE_UNCONDITIONAL", false, false, true, false, false, false, true};
    inline const FlowType CALLOTHER_OVERRIDE_CALL{RefType::__CALLOTHER_OVERRIDE_CALL, "CALLOTHER_OVERRIDE_CALL", true, true, false, false, false, false, true};
    inline const FlowType CALLOTHER_OVERRIDE_JUMP{RefType::__CALLOTHER_OVERRIDE_JUMP, "CALLOTHER_OVERRIDE_JUMP", false, false, true, false, false, false, true};

    // Data reference types
    inline const DataRefType THUNK{RefType::__DYNAMICDATA, "THUNK", 0};
    inline const DataRefType DATA{RefType::__UNKNOWNDATA, "DATA", 0};
    inline const DataRefType PARAM{RefType::__UNKNOWNPARAM, "PARAM", 0};
    inline const DataRefType DATA_IND{RefType::__UNKNOWNDATA_IND, "DATA_IND", DataRefType::INDX};
    inline const DataRefType READ{RefType::__READ, "READ", DataRefType::READX};
    inline const DataRefType WRITE{RefType::__WRITE, "WRITE", DataRefType::WRITEX};
    inline const DataRefType READ_WRITE{RefType::__READ_WRITE, "READ_WRITE", DataRefType::READX | DataRefType::WRITEX};
    inline const DataRefType READ_IND{RefType::__READ_IND, "READ_IND", DataRefType::READX | DataRefType::INDX};
    inline const DataRefType WRITE_IND{RefType::__WRITE_IND, "WRITE_IND", DataRefType::WRITEX | DataRefType::INDX};
    inline const DataRefType READ_WRITE_IND{RefType::__READ_WRITE_IND, "READ_WRITE_IND", DataRefType::READX | DataRefType::WRITEX | DataRefType::INDX};
    inline const DataRefType EXTERNAL_REF{RefType::__EXTERNAL_REF, "EXTERNAL", 0};

} // namespace RefTypes

} // namespace ghidra
