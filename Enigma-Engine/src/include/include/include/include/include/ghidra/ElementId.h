/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ElementId.h
/// \brief XML element identifier for Pcode data elements
#pragma once

#include <string>

namespace ghidra {

struct ElementId {
    std::string name;
    int id;

    ElementId() : name(), id(0) {}
    ElementId(const std::string& name, int id) : name(name), id(id) {}

    bool operator==(const ElementId& other) const { return id == other.id; }
    bool operator!=(const ElementId& other) const { return id != other.id; }
};

extern const ElementId ELEM_RANGELIST;
extern const ElementId ELEM_RANGE;
extern const ElementId ELEM_DATA;
extern const ElementId ELEM_INPUT;
extern const ElementId ELEM_OFF;
extern const ElementId ELEM_OUTPUT;
extern const ElementId ELEM_RETURNADDRESS;
extern const ElementId ELEM_SYMBOL;
extern const ElementId ELEM_TARGET;
extern const ElementId ELEM_VAL;
extern const ElementId ELEM_VALUE;
extern const ElementId ELEM_VOID;
extern const ElementId ELEM_USEROP;
extern const ElementId ELEM_USEROP_HEAD;
extern const ElementId ELEM_UNKNOWN;

// block graph element ids
extern const ElementId ELEM_BLOCK;
extern const ElementId ELEM_BHEAD;
extern const ElementId ELEM_EDGE;

// model.lang inject payload element ids
extern const ElementId ELEM_CONTEXT;
extern const ElementId ELEM_CALLFIXUP;
extern const ElementId ELEM_CALLOTHERFIXUP;
extern const ElementId ELEM_SEGMENTOP;
extern const ElementId ELEM_CONSTRESOLVE;
extern const ElementId ELEM_VARNODE;
extern const ElementId ELEM_RESOLVEPROTOTYPE;
extern const ElementId ELEM_MODEL;

// model rule element ids
extern const ElementId ELEM_DATATYPE;
extern const ElementId ELEM_CONVERT_TO_PTR;

// protorules element ids
extern const ElementId ELEM_HIDDEN_RETURN;
extern const ElementId ELEM_CONSUME;
extern const ElementId ELEM_GOTO_STACK;
extern const ElementId ELEM_EXTRA_STACK;
extern const ElementId ELEM_DATATYPE_AT;
extern const ElementId ELEM_POSITION;
extern const ElementId ELEM_VARARGS;
extern const ElementId ELEM_CONSUME_EXTRA;
extern const ElementId ELEM_CONSUME_REMAINING;
extern const ElementId ELEM_JOIN;
extern const ElementId ELEM_JOIN_PER_PRIMITIVE;
extern const ElementId ELEM_JOIN_DUAL_CLASS;

// context setting element ids
extern const ElementId ELEM_SET;
extern const ElementId ELEM_CONTEXT_SET;
extern const ElementId ELEM_TRACKED_SET;
extern const ElementId ELEM_CONTEXT_DATA;

// model.pcode symbol map family element ids
extern const ElementId ELEM_HASH;
extern const ElementId ELEM_FACETSYMBOL;
extern const ElementId ELEM_ADDR;

// model.pcode jump-table / param-measure element ids (W145)
extern const ElementId ELEM_RANK;
extern const ElementId ELEM_JUMPTABLE;
extern const ElementId ELEM_LOADTABLE;
extern const ElementId ELEM_BASICOVERRIDE;
extern const ElementId ELEM_DEST;

} // namespace ghidra
