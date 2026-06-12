/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ElementId.cpp
/// \brief XML element identifier for Pcode data elements
#include "ghidra/ElementId.h"

namespace ghidra {

const ElementId ELEM_RANGELIST("rangelist", 1);
const ElementId ELEM_RANGE("range", 2);
const ElementId ELEM_DATA("data", 3);
const ElementId ELEM_INPUT("input", 4);
const ElementId ELEM_OFF("off", 5);
const ElementId ELEM_OUTPUT("output", 6);
const ElementId ELEM_RETURNADDRESS("returnaddress", 7);
const ElementId ELEM_SYMBOL("symbol", 8);
const ElementId ELEM_TARGET("target", 9);
const ElementId ELEM_VAL("val", 10);
const ElementId ELEM_VALUE("value", 11);
const ElementId ELEM_VOID("void", 12);
const ElementId ELEM_USEROP("userop", 14);
const ElementId ELEM_USEROP_HEAD("userop_head", 15);
const ElementId ELEM_UNKNOWN("XMLunknown", 13);

// block graph element ids
const ElementId ELEM_BLOCK("block", 200);
const ElementId ELEM_BHEAD("bhead", 201);
const ElementId ELEM_EDGE("edge", 202);

// model.lang inject payload element ids
const ElementId ELEM_CONTEXT("context", 121);
const ElementId ELEM_CALLFIXUP("callfixup", 203);
const ElementId ELEM_CALLOTHERFIXUP("callotherfixup", 204);
const ElementId ELEM_SEGMENTOP("segmentop", 205);
const ElementId ELEM_CONSTRESOLVE("constresolve", 206);
const ElementId ELEM_VARNODE("varnode", 207);
const ElementId ELEM_RESOLVEPROTOTYPE("resolveprototype", 208);
const ElementId ELEM_MODEL("model", 209);

// model rule element ids
const ElementId ELEM_DATATYPE("datatype", 273);
const ElementId ELEM_CONVERT_TO_PTR("convert_to_ptr", 276);

// protorules element ids
const ElementId ELEM_HIDDEN_RETURN("hidden_return", 100);
const ElementId ELEM_CONSUME("consume", 101);
const ElementId ELEM_GOTO_STACK("goto_stack", 102);
const ElementId ELEM_EXTRA_STACK("extra_stack", 103);
const ElementId ELEM_DATATYPE_AT("datatype_at", 104);
const ElementId ELEM_POSITION("position", 105);
const ElementId ELEM_VARARGS("varargs", 106);
const ElementId ELEM_CONSUME_EXTRA("consume_extra", 107);
const ElementId ELEM_CONSUME_REMAINING("consume_remaining", 108);
const ElementId ELEM_JOIN("join", 109);
const ElementId ELEM_JOIN_PER_PRIMITIVE("join_per_primitive", 110);
const ElementId ELEM_JOIN_DUAL_CLASS("join_dual_class", 111);
const ElementId ELEM_SET("set", 112);
const ElementId ELEM_CONTEXT_SET("context_set", 113);
const ElementId ELEM_TRACKED_SET("tracked_set", 114);
const ElementId ELEM_CONTEXT_DATA("context_data", 115);

// model.pcode jump-table/param-measure element ids (W145)
const ElementId ELEM_RANK("rank", 116);
const ElementId ELEM_JUMPTABLE("jumptable", 117);
const ElementId ELEM_LOADTABLE("loadtable", 118);
const ElementId ELEM_BASICOVERRIDE("basicoverride", 119);
const ElementId ELEM_DEST("dest", 120);

// model.pcode symbol map family element ids
const ElementId ELEM_HASH("hash", 274);
const ElementId ELEM_FACETSYMBOL("facetsymbol", 275);
const ElementId ELEM_ADDR("addr", 277);

} // namespace ghidra
