/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AttributeId.cpp
/// \brief XML attribute identifier for Pcode data elements
#include "ghidra/AttributeId.h"

namespace ghidra {

const AttributeId ATTRIB_CONTENT("XMLcontent", 1);
const AttributeId ATTRIB_ALIGN("align", 2);
const AttributeId ATTRIB_BIGENDIAN("bigendian", 3);
const AttributeId ATTRIB_CONSTRUCTOR("constructor", 4);
const AttributeId ATTRIB_DESTRUCTOR("destructor", 5);
const AttributeId ATTRIB_EXTRAPOP("extrapop", 6);
const AttributeId ATTRIB_FORMAT("format", 7);
const AttributeId ATTRIB_HIDDENRETPARM("hiddenretparm", 8);
const AttributeId ATTRIB_ID("id", 9);
const AttributeId ATTRIB_INDEX("index", 10);
const AttributeId ATTRIB_INDIRECTSTORAGE("indirectstorage", 11);
const AttributeId ATTRIB_METATYPE("metatype", 12);
const AttributeId ATTRIB_MODEL("model", 13);
const AttributeId ATTRIB_NAME("name", 14);
const AttributeId ATTRIB_NAMELOCK("namelock", 15);
const AttributeId ATTRIB_OFFSET("offset", 16);
const AttributeId ATTRIB_READONLY("readonly", 17);
const AttributeId ATTRIB_REF("ref", 18);
const AttributeId ATTRIB_SIZE("size", 19);
const AttributeId ATTRIB_SPACE("space", 20);
const AttributeId ATTRIB_THISPTR("thisptr", 21);
const AttributeId ATTRIB_TYPE("type", 22);
const AttributeId ATTRIB_TYPELOCK("typelock", 23);
const AttributeId ATTRIB_VAL("val", 24);
const AttributeId ATTRIB_VALUE("value", 25);
const AttributeId ATTRIB_WORDSIZE("wordsize", 26);

const AttributeId ATTRIB_FIRST("first", 27);
const AttributeId ATTRIB_LAST("last", 28);
const AttributeId ATTRIB_UNIQ("uniq", 29);

const AttributeId ATTRIB_ADDRTIED("addrtied", 30);
const AttributeId ATTRIB_GRP("grp", 31);
const AttributeId ATTRIB_INPUT("input", 32);
const AttributeId ATTRIB_PERSISTS("persists", 33);
const AttributeId ATTRIB_UNAFF("unaff", 34);

const AttributeId ATTRIB_BLOCKREF("blockref", 35);
const AttributeId ATTRIB_CLOSE("close", 36);
const AttributeId ATTRIB_COLOR("color", 37);
const AttributeId ATTRIB_INDENT("indent", 38);
const AttributeId ATTRIB_OFF("off", 39);
const AttributeId ATTRIB_OPEN("open", 40);
const AttributeId ATTRIB_OPREF("opref", 41);
const AttributeId ATTRIB_VARREF("varref", 42);

const AttributeId ATTRIB_CODE("code", 43);
const AttributeId ATTRIB_CONTAIN("contain", 44);
const AttributeId ATTRIB_DEFAULTSPACE("defaultspace", 45);
const AttributeId ATTRIB_UNIQBASE("uniqbase", 46);

const AttributeId ATTRIB_ALIGNMENT("alignment", 47);
const AttributeId ATTRIB_ARRAYSIZE("arraysize", 48);
const AttributeId ATTRIB_CHAR("char", 49);
const AttributeId ATTRIB_CORE("core", 50);
const AttributeId ATTRIB_INCOMPLETE("incomplete", 52);
const AttributeId ATTRIB_OPAQUESTRING("opaquestring", 56);
const AttributeId ATTRIB_SIGNED("signed", 57);
const AttributeId ATTRIB_STRUCTALIGN("structalign", 58);
const AttributeId ATTRIB_UTF("utf", 59);
const AttributeId ATTRIB_VARLENGTH("varlength", 60);

const AttributeId ATTRIB_CAT("cat", 61);
const AttributeId ATTRIB_FIELD("field", 62);
const AttributeId ATTRIB_MERGE("merge", 63);
const AttributeId ATTRIB_SCOPE("scope", 160);
const AttributeId ATTRIB_SCOPEIDBYNAME("scopeidbyname", 64);
const AttributeId ATTRIB_VOLATILE("volatile", 65);

const AttributeId ATTRIB_CLASS("class", 66);
const AttributeId ATTRIB_REPREF("repref", 67);
const AttributeId ATTRIB_SYMREF("symref", 68);

const AttributeId ATTRIB_TRUNC("trunc", 69);

const AttributeId ATTRIB_DYNAMIC("dynamic", 70);
const AttributeId ATTRIB_INCIDENTALCOPY("incidentalcopy", 71);
const AttributeId ATTRIB_INJECT("inject", 72);
const AttributeId ATTRIB_PARAMSHIFT("paramshift", 73);
const AttributeId ATTRIB_TARGETOP("targetop", 74);

const AttributeId ATTRIB_ALTINDEX("altindex", 75);
const AttributeId ATTRIB_DEPTH("depth", 76);
const AttributeId ATTRIB_END("end", 77);
const AttributeId ATTRIB_OPCODE("opcode", 78);
const AttributeId ATTRIB_REV("rev", 79);

const AttributeId ATTRIB_A("a", 80);
const AttributeId ATTRIB_B("b", 81);
const AttributeId ATTRIB_LENGTH("length", 82);
const AttributeId ATTRIB_TAG("tag", 83);

const AttributeId ATTRIB_NOCODE("nocode", 84);

const AttributeId ATTRIB_FARPOINTER("farpointer", 85);
const AttributeId ATTRIB_INPUTOP("inputop", 86);
const AttributeId ATTRIB_OUTPUTOP("outputop", 87);
const AttributeId ATTRIB_USEROP("userop", 88);

const AttributeId ATTRIB_BASE("base", 89);
const AttributeId ATTRIB_DELAY("delay", 91);
const AttributeId ATTRIB_LOGICALSIZE("logicalsize", 92);
const AttributeId ATTRIB_PHYSICAL("physical", 93);
const AttributeId ATTRIB_PIECE("piece", 94);

const AttributeId ATTRIB_ADJUSTVMA("adjustvma", 103);
const AttributeId ATTRIB_ENABLE("enable", 104);
const AttributeId ATTRIB_GROUP("group", 105);
const AttributeId ATTRIB_GROWTH("growth", 106);
const AttributeId ATTRIB_KEY("key", 107);
const AttributeId ATTRIB_LOADERSYMBOLS("loadersymbols", 108);
const AttributeId ATTRIB_PARENT("parent", 109);
const AttributeId ATTRIB_REGISTER("register", 110);
const AttributeId ATTRIB_REVERSEJUSTIFY("reversejustify", 111);
const AttributeId ATTRIB_SIGNEXT("signext", 112);
const AttributeId ATTRIB_STYLE("style", 113);

const AttributeId ATTRIB_CUSTOM("custom", 114);
const AttributeId ATTRIB_DOTDOTDOT("dotdotdot", 115);
const AttributeId ATTRIB_EXTENSION("extension", 116);
const AttributeId ATTRIB_HASTHIS("hasthis", 117);
const AttributeId ATTRIB_INLINE("inline", 118);
const AttributeId ATTRIB_KILLEDBYCALL("killedbycall", 119);
const AttributeId ATTRIB_MAXSIZE("maxsize", 120);
const AttributeId ATTRIB_MINSIZE("minsize", 121);
const AttributeId ATTRIB_MODELLOCK("modellock", 122);
const AttributeId ATTRIB_NORETURN("noreturn", 123);
const AttributeId ATTRIB_POINTERMAX("pointermax", 124);
const AttributeId ATTRIB_SEPARATEFLOAT("separatefloat", 125);
const AttributeId ATTRIB_STACKSHIFT("stackshift", 126);
const AttributeId ATTRIB_STRATEGY("strategy", 127);
const AttributeId ATTRIB_THISBEFORERETPOINTER("thisbeforeretpointer", 128);
const AttributeId ATTRIB_VOIDLOCK("voidlock", 129);

const AttributeId ATTRIB_VECTOR_LANE_SIZES("vector_lane_sizes", 130);

const AttributeId ATTRIB_LABEL("label", 131);
const AttributeId ATTRIB_NUM("num", 132);

const AttributeId ATTRIB_LOCK("lock", 133);
const AttributeId ATTRIB_MAIN("main", 134);

const AttributeId ATTRIB_BADDATA("baddata", 145);
const AttributeId ATTRIB_HASH("hash", 146);
const AttributeId ATTRIB_UNIMPL("unimpl", 147);

const AttributeId ATTRIB_STORAGE("storage", 149);
const AttributeId ATTRIB_STACKSPILL("stackspill", 150);

const AttributeId ATTRIB_SIZES("sizes", 151);
const AttributeId ATTRIB_BACKFILL("backfill", 152);
const AttributeId ATTRIB_MAX_PRIMITIVES("maxprimitives", 153);
const AttributeId ATTRIB_REVERSESIGNIF("reversesignif", 154);
const AttributeId ATTRIB_MATCHSIZE("matchsize", 155);
const AttributeId ATTRIB_AFTER_BYTES("afterbytes", 156);
const AttributeId ATTRIB_AFTER_STORAGE("afterstorage", 157);
const AttributeId ATTRIB_FILL_ALTERNATE("fillalternate", 158);

const AttributeId ATTRIB_UNKNOWN("XMLunknown", 159);

} // namespace ghidra
