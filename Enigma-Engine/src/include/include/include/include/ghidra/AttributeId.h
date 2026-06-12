/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file AttributeId.h
/// \brief XML attribute identifier for Pcode data elements
/// Translated from: ghidra.program.model.pcode.AttributeId
#pragma once

#include <string>

namespace ghidra {

struct AttributeId {
    std::string name;
    int id;

    AttributeId() : name(), id(0) {}
    AttributeId(const std::string& name, int id) : name(name), id(id) {}
};

extern const AttributeId ATTRIB_CONTENT;
extern const AttributeId ATTRIB_ALIGN;
extern const AttributeId ATTRIB_BIGENDIAN;
extern const AttributeId ATTRIB_CONSTRUCTOR;
extern const AttributeId ATTRIB_DESTRUCTOR;
extern const AttributeId ATTRIB_EXTRAPOP;
extern const AttributeId ATTRIB_FORMAT;
extern const AttributeId ATTRIB_HIDDENRETPARM;
extern const AttributeId ATTRIB_ID;
extern const AttributeId ATTRIB_INDEX;
extern const AttributeId ATTRIB_INDIRECTSTORAGE;
extern const AttributeId ATTRIB_METATYPE;
extern const AttributeId ATTRIB_MODEL;
extern const AttributeId ATTRIB_NAME;
extern const AttributeId ATTRIB_NAMELOCK;
extern const AttributeId ATTRIB_OFFSET;
extern const AttributeId ATTRIB_READONLY;
extern const AttributeId ATTRIB_REF;
extern const AttributeId ATTRIB_SIZE;
extern const AttributeId ATTRIB_SPACE;
extern const AttributeId ATTRIB_THISPTR;
extern const AttributeId ATTRIB_TYPE;
extern const AttributeId ATTRIB_TYPELOCK;
extern const AttributeId ATTRIB_VAL;
extern const AttributeId ATTRIB_VALUE;
extern const AttributeId ATTRIB_WORDSIZE;

extern const AttributeId ATTRIB_FIRST;
extern const AttributeId ATTRIB_LAST;
extern const AttributeId ATTRIB_UNIQ;

extern const AttributeId ATTRIB_ADDRTIED;
extern const AttributeId ATTRIB_GRP;
extern const AttributeId ATTRIB_INPUT;
extern const AttributeId ATTRIB_PERSISTS;
extern const AttributeId ATTRIB_UNAFF;

extern const AttributeId ATTRIB_BLOCKREF;
extern const AttributeId ATTRIB_CLOSE;
extern const AttributeId ATTRIB_COLOR;
extern const AttributeId ATTRIB_INDENT;
extern const AttributeId ATTRIB_OFF;
extern const AttributeId ATTRIB_OPEN;
extern const AttributeId ATTRIB_OPREF;
extern const AttributeId ATTRIB_VARREF;

extern const AttributeId ATTRIB_CODE;
extern const AttributeId ATTRIB_CONTAIN;
extern const AttributeId ATTRIB_DEFAULTSPACE;
extern const AttributeId ATTRIB_UNIQBASE;

extern const AttributeId ATTRIB_ALIGNMENT;
extern const AttributeId ATTRIB_ARRAYSIZE;
extern const AttributeId ATTRIB_CHAR;
extern const AttributeId ATTRIB_CORE;
extern const AttributeId ATTRIB_INCOMPLETE;
extern const AttributeId ATTRIB_OPAQUESTRING;
extern const AttributeId ATTRIB_SIGNED;
extern const AttributeId ATTRIB_STRUCTALIGN;
extern const AttributeId ATTRIB_UTF;
extern const AttributeId ATTRIB_VARLENGTH;

extern const AttributeId ATTRIB_CAT;
extern const AttributeId ATTRIB_FIELD;
extern const AttributeId ATTRIB_MERGE;
extern const AttributeId ATTRIB_SCOPE;
extern const AttributeId ATTRIB_SCOPEIDBYNAME;
extern const AttributeId ATTRIB_VOLATILE;

extern const AttributeId ATTRIB_CLASS;
extern const AttributeId ATTRIB_REPREF;
extern const AttributeId ATTRIB_SYMREF;

extern const AttributeId ATTRIB_TRUNC;

extern const AttributeId ATTRIB_DYNAMIC;
extern const AttributeId ATTRIB_INCIDENTALCOPY;
extern const AttributeId ATTRIB_INJECT;
extern const AttributeId ATTRIB_PARAMSHIFT;
extern const AttributeId ATTRIB_TARGETOP;

extern const AttributeId ATTRIB_ALTINDEX;
extern const AttributeId ATTRIB_DEPTH;
extern const AttributeId ATTRIB_END;
extern const AttributeId ATTRIB_OPCODE;
extern const AttributeId ATTRIB_REV;

extern const AttributeId ATTRIB_A;
extern const AttributeId ATTRIB_B;
extern const AttributeId ATTRIB_LENGTH;
extern const AttributeId ATTRIB_TAG;

extern const AttributeId ATTRIB_NOCODE;

extern const AttributeId ATTRIB_FARPOINTER;
extern const AttributeId ATTRIB_INPUTOP;
extern const AttributeId ATTRIB_OUTPUTOP;
extern const AttributeId ATTRIB_USEROP;

extern const AttributeId ATTRIB_BASE;
extern const AttributeId ATTRIB_DELAY;
extern const AttributeId ATTRIB_LOGICALSIZE;
extern const AttributeId ATTRIB_PHYSICAL;
extern const AttributeId ATTRIB_PIECE;

extern const AttributeId ATTRIB_ADJUSTVMA;
extern const AttributeId ATTRIB_ENABLE;
extern const AttributeId ATTRIB_GROUP;
extern const AttributeId ATTRIB_GROWTH;
extern const AttributeId ATTRIB_KEY;
extern const AttributeId ATTRIB_LOADERSYMBOLS;
extern const AttributeId ATTRIB_PARENT;
extern const AttributeId ATTRIB_REGISTER;
extern const AttributeId ATTRIB_REVERSEJUSTIFY;
extern const AttributeId ATTRIB_SIGNEXT;
extern const AttributeId ATTRIB_STYLE;

extern const AttributeId ATTRIB_CUSTOM;
extern const AttributeId ATTRIB_DOTDOTDOT;
extern const AttributeId ATTRIB_EXTENSION;
extern const AttributeId ATTRIB_HASTHIS;
extern const AttributeId ATTRIB_INLINE;
extern const AttributeId ATTRIB_KILLEDBYCALL;
extern const AttributeId ATTRIB_MAXSIZE;
extern const AttributeId ATTRIB_MINSIZE;
extern const AttributeId ATTRIB_MODELLOCK;
extern const AttributeId ATTRIB_NORETURN;
extern const AttributeId ATTRIB_POINTERMAX;
extern const AttributeId ATTRIB_SEPARATEFLOAT;
extern const AttributeId ATTRIB_STACKSHIFT;
extern const AttributeId ATTRIB_STRATEGY;
extern const AttributeId ATTRIB_THISBEFORERETPOINTER;
extern const AttributeId ATTRIB_VOIDLOCK;

extern const AttributeId ATTRIB_VECTOR_LANE_SIZES;

extern const AttributeId ATTRIB_LABEL;
extern const AttributeId ATTRIB_NUM;

extern const AttributeId ATTRIB_LOCK;
extern const AttributeId ATTRIB_MAIN;

extern const AttributeId ATTRIB_BADDATA;
extern const AttributeId ATTRIB_HASH;
extern const AttributeId ATTRIB_UNIMPL;

extern const AttributeId ATTRIB_STORAGE;
extern const AttributeId ATTRIB_STACKSPILL;

extern const AttributeId ATTRIB_SIZES;
extern const AttributeId ATTRIB_BACKFILL;
extern const AttributeId ATTRIB_MAX_PRIMITIVES;
extern const AttributeId ATTRIB_REVERSESIGNIF;
extern const AttributeId ATTRIB_MATCHSIZE;
extern const AttributeId ATTRIB_AFTER_BYTES;
extern const AttributeId ATTRIB_AFTER_STORAGE;
extern const AttributeId ATTRIB_FILL_ALTERNATE;

extern const AttributeId ATTRIB_UNKNOWN;

} // namespace ghidra
