/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeWriter.cpp
/// \brief Implementation of DataTypeWriter.
#include "ghidra/DataTypeWriter.h"

#include <ghidra/DataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/Composite.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/Enum.h>
#include <ghidra/TypeDef.h>
#include <ghidra/FunctionDefinition.h>
#include <ghidra/FunctionSignature.h>
#include <ghidra/ParameterDefinition.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/Dynamic.h>
#include <ghidra/FactoryDataType.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/TaskMonitor.h>

#include <ostream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace ghidra {

const std::string DataTypeWriter::EOL = "\n";

DataTypeWriter::DataTypeWriter(DataTypeManager* dtm, std::ostream& out, bool cppStyleComments)
    : out_(out), dtm_(dtm), cppStyleComments_(cppStyleComments) {}

bool DataTypeWriter::isResolved(const std::string& typeName) const {
    return inProgress_.count(typeName) > 0;
}

std::string DataTypeWriter::comment(const std::string& text) const {
    if (text.empty()) return "";
    if (cppStyleComments_) return "// " + text;
    return "/* " + text + " */";
}

std::string DataTypeWriter::escapeName(const std::string& name) {
    return name;
}

std::string DataTypeWriter::getBaseTypeName(DataType* dt) {
    if (!dt) return "void";
    return dt->getName();
}

int DataTypeWriter::getPointerDepth(Pointer* p) {
    int depth = 0;
    DataType* cur = p;
    while (cur && dynamic_cast<Pointer*>(cur)) {
        ++depth;
        cur = dynamic_cast<Pointer*>(cur)->getDataType();
    }
    return depth;
}

void DataTypeWriter::write(DataType* dt, TaskMonitor* monitor) {
    if (!dt) return;
    doWrite(dt, monitor);
    emitPending();
}

void DataTypeWriter::write(const std::vector<DataType*>& types, TaskMonitor* monitor) {
    if (monitor) monitor->initialize(static_cast<int64_t>(types.size()));
    int i = 0;
    for (auto* dt : types) {
        if (dt) doWrite(dt, monitor);
        if (monitor) monitor->setProgress(++i);
    }
    emitPending();
}

void DataTypeWriter::doWrite(DataType* dt, TaskMonitor* monitor) {
    if (!dt) return;
    if (monitor && monitor->isCancelled()) return;

    if (dt->getName() == "void") return; // built-in, no decl

    if (auto* fd = dynamic_cast<FunctionDefinition*>(dt)) {
        writeFunctionDef(fd);
        return;
    }
    if (dynamic_cast<FactoryDataType*>(dt)) {
        return;
    }
    if (dynamic_cast<Pointer*>(dt)) {
        writePointer(dynamic_cast<Pointer*>(dt));
        return;
    }
    if (dynamic_cast<Array*>(dt)) {
        writeArray(dynamic_cast<Array*>(dt));
        return;
    }
    if (dynamic_cast<BitFieldDataType*>(dt)) {
        writeBitField(dynamic_cast<BitFieldDataType*>(dt));
        return;
    }
    if (dynamic_cast<Dynamic*>(dt)) {
        writeDynamic(dynamic_cast<Dynamic*>(dt));
        return;
    }

    if (inProgress_.count(dt->getName()) > 0) return;

    if (auto* s = dynamic_cast<Structure*>(dt)) {
        writeCompositePreDeclaration(s);
        return;
    }
    if (auto* u = dynamic_cast<Union*>(dt)) {
        writeCompositePreDeclaration(u);
        return;
    }
    if (auto* e = dynamic_cast<Enum*>(dt)) {
        writeEnumPreDeclaration(e);
        return;
    }
    if (auto* td = dynamic_cast<TypeDef*>(dt)) {
        writeTypedef(td);
        return;
    }

    // Unknown leaf: emit a typedef-style forward decl with the type's name
    out_ << "typedef " << dt->getDisplayName() << " " << escapeName(dt->getName()) << ";"
         << EOL << EOL;
    inProgress_.insert(dt->getName());
    defined_.insert(dt->getName());
}

void DataTypeWriter::writeBuiltInDecl(const std::string& name) {
    // No-op in this simplified port; built-in typedefs are emitted lazily
    // when first referenced.
    (void)name;
}

void DataTypeWriter::writeCompositePreDeclaration(Composite* c) {
    if (!c) return;
    if (inProgress_.count(c->getName()) > 0) return;
    if (forwardDeclared_.count(c->getName()) == 0) {
        std::string kw = dynamic_cast<Union*>(c) ? "union" : "struct";
        out_ << kw << " " << escapeName(c->getName()) << ";" << EOL;
        forwardDeclared_.insert(c->getName());
    }
    // Mark as in-progress immediately to break recursion: doWrite on a self-
    // referencing composite will short-circuit and the actual definition is
    // emitted from emitPending().
    inProgress_.insert(c->getName());
    pendingComposites_.push_back(c);

    // Recurse into component types so they get emitted before our definition
    int n = c->getNumComponents();
    for (int i = 0; i < n; ++i) {
        DataTypeComponent* comp = c->getComponent(i);
        if (comp) {
            DataType* cdt = comp->getDataType();
            if (cdt) doWrite(cdt, nullptr);
        }
    }
}

void DataTypeWriter::writeStruct(Structure* s) {
    if (!s) return;
    out_ << "struct " << escapeName(s->getName()) << " {" << EOL;
    int n = s->getNumComponents();
    for (int i = 0; i < n; ++i) {
        DataTypeComponent* comp = s->getComponent(i);
        if (!comp) continue;
        DataType* cdt = comp->getDataType();
        if (!cdt) continue;
        std::string fcmt = comp->getComment();
        std::string pathCmt = comment(s->getName() + "." + comp->getFieldName());
        if (!fcmt.empty()) out_ << "    " << comment(fcmt) << EOL;
        else if (!pathCmt.empty()) out_ << "    " << pathCmt << EOL;
        out_ << "    " << cdt->getDisplayName();
        std::string fname = comp->getFieldName();
        if (!fname.empty()) out_ << " " << fname;
        out_ << ";" << EOL;
    }
    out_ << "};" << EOL << EOL;
}

void DataTypeWriter::writeUnion(Union* u) {
    if (!u) return;
    out_ << "union " << escapeName(u->getName()) << " {" << EOL;
    int n = u->getNumComponents();
    for (int i = 0; i < n; ++i) {
        DataTypeComponent* comp = u->getComponent(i);
        if (!comp) continue;
        DataType* cdt = comp->getDataType();
        if (!cdt) continue;
        std::string fcmt = comp->getComment();
        std::string pathCmt = comment(u->getName() + "." + comp->getFieldName());
        if (!fcmt.empty()) out_ << "    " << comment(fcmt) << EOL;
        else if (!pathCmt.empty()) out_ << "    " << pathCmt << EOL;
        out_ << "    " << cdt->getDisplayName();
        std::string fname = comp->getFieldName();
        if (!fname.empty()) out_ << " " << fname;
        out_ << ";" << EOL;
    }
    out_ << "};" << EOL << EOL;
}

void DataTypeWriter::writeEnumPreDeclaration(Enum* e) {
    if (!e) return;
    if (inProgress_.count(e->getName()) > 0) return;
    if (forwardDeclared_.count(e->getName()) == 0) {
        out_ << "enum " << escapeName(e->getName()) << ";" << EOL;
        forwardDeclared_.insert(e->getName());
    }
    inProgress_.insert(e->getName());
    pendingEnums_.push_back(e);
}

void DataTypeWriter::writeEnum(Enum* e) {
    if (!e) return;
    out_ << "typedef enum " << escapeName(e->getName()) << " {" << EOL;
    auto names = e->getNames();
    auto values = e->getValues();
    size_t n = std::min(names.size(), values.size());
    for (size_t i = 0; i < n; ++i) {
        out_ << "    " << escapeName(names[i]) << " = " << values[i];
        if (i + 1 < n) out_ << ",";
        out_ << EOL;
    }
    out_ << "} " << escapeName(e->getName()) << ";" << EOL << EOL;
}

void DataTypeWriter::writeTypedef(TypeDef* td) {
    if (!td) return;
    if (inProgress_.count(td->getName()) > 0) return;
    inProgress_.insert(td->getName());
    DataType* base = td->getBaseDataType();
    if (!base) base = td->getDataType();
    if (base) doWrite(base, nullptr);

    // If the underlying type is a composite or enum, we want a typedef
    // line that aliases it. The composite/enum must be already resolved
    // (or pending for definition) so the name is in scope.
    out_ << "typedef " << (base ? base->getDisplayName() : "void")
         << " " << escapeName(td->getName()) << ";" << EOL << EOL;
}

void DataTypeWriter::writePointer(Pointer* p) {
    if (!p) return;
    if (inProgress_.count(p->getName()) > 0) return;
    inProgress_.insert(p->getName());
    DataType* inner = p->getDataType();
    if (inner) doWrite(inner, nullptr);

    // If the inner type is a function definition, emit a function pointer
    // type declaration.
    if (auto* fd = dynamic_cast<FunctionDefinition*>(inner)) {
        std::ostringstream sig;
        sig << "typedef ";
        DataType* rt = fd->getReturnType();
        sig << (rt ? rt->getDisplayName() : "void") << " (*"
            << escapeName(p->getName()) << ")(";
        auto args = fd->getArguments();
        for (size_t i = 0; i < args.size(); ++i) {
            if (i > 0) sig << ", ";
            DataType* adt = args[i]->getDataType();
            sig << (adt ? adt->getDisplayName() : "void")
                << " " << args[i]->getName();
        }
        if (args.empty() && !fd->hasVarArgs()) sig << "void";
        if (fd->hasVarArgs()) {
            if (!args.empty()) sig << ", ";
            sig << "...";
        }
        sig << ")";
        out_ << sig.str() << ";" << EOL << EOL;
        return;
    }

    // Plain pointer: just a forward declaration of the pointed-to type
    // (already handled by doWrite(inner) above) and a typedef alias for
    // the pointer name itself, mirroring the Ghidra convention.
    int depth = getPointerDepth(p);
    std::string innerName = inner ? inner->getDisplayName() : "void";
    std::string stars(static_cast<size_t>(depth), '*');
    out_ << "typedef " << innerName << " " << stars
         << " " << escapeName(p->getName()) << ";" << EOL << EOL;
}

void DataTypeWriter::writeArray(Array* a) {
    if (!a) return;
    if (inProgress_.count(a->getName()) > 0) return;
    inProgress_.insert(a->getName());
    DataType* inner = a->getDataType();
    if (inner) doWrite(inner, nullptr);
    int n = a->getNumElements();
    out_ << "typedef " << (inner ? inner->getDisplayName() : "void")
         << " " << escapeName(a->getName()) << "[" << n << "];"
         << EOL << EOL;
}

void DataTypeWriter::writeFunctionDef(FunctionDefinition* fd) {
    if (!fd) return;
    std::string fdName = static_cast<DataType*>(fd)->getName();
    if (inProgress_.count(fdName) > 0) return;
    inProgress_.insert(fdName);
    std::ostringstream sig;
    DataType* rt = fd->getReturnType();
    sig << "typedef " << (rt ? rt->getDisplayName() : "void") << " (*"
        << escapeName(fdName) << ")(";
    auto args = fd->getArguments();
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) sig << ", ";
        DataType* adt = args[i]->getDataType();
        sig << (adt ? adt->getDisplayName() : "void") << " " << args[i]->getName();
    }
    if (args.empty() && !fd->hasVarArgs()) sig << "void";
    if (fd->hasVarArgs()) {
        if (!args.empty()) sig << ", ";
        sig << "...";
    }
    sig << ")";
    out_ << sig.str() << ";" << EOL << EOL;
}

void DataTypeWriter::writeBitField(BitFieldDataType* bf) {
    if (!bf) return;
    DataType* base = bf->getBaseDataType();
    if (base) doWrite(base, nullptr);
    out_ << "/* bitfield: " << bf->getName() << " ("
         << bf->getBitSize() << " bits) */" << EOL;
}

void DataTypeWriter::writeDynamic(Dynamic* d) {
    if (!d) return;
    out_ << "/* dynamic: " << d->getName() << " */" << EOL;
}

void DataTypeWriter::emitPending() {
    // Enums first (no cycles), then composites in order, then typedefs.
    for (auto* e : pendingEnums_) {
        if (defined_.count(e->getName()) == 0) {
            writeEnum(e);
            defined_.insert(e->getName());
        }
    }
    pendingEnums_.clear();

    for (auto* c : pendingComposites_) {
        if (defined_.count(c->getName()) > 0) continue;
        if (auto* s = dynamic_cast<Structure*>(c)) writeStruct(s);
        else if (auto* u = dynamic_cast<Union*>(c)) writeUnion(u);
        defined_.insert(c->getName());
    }
    pendingComposites_.clear();

    for (auto* td : pendingTypedefs_) {
        if (defined_.count(td->getName()) == 0) {
            writeTypedef(td);
            defined_.insert(td->getName());
        }
    }
    pendingTypedefs_.clear();
}

} // namespace ghidra
