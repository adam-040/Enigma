/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/BasicCompilerSpec.h>
#include <ghidra/SleighLanguage.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/PrototypeModel.h>

namespace ghidra {

BasicCompilerSpec::BasicCompilerSpec(CompilerSpecDescription* description, SleighLanguage* language)
    : CompilerSpec(description->getCompilerSpecID()),
      description_(description), language_(language) {
    setName(description->getCompilerSpecName());
}

PrototypeModel* BasicCompilerSpec::matchConvention(const std::string& name) {
    if (name.empty() || name == "default" || name == "unknown") {
        return getDefaultCallingConvention();
    }
    for (auto* m : models_) {
        if (m->getName() == name) return m;
    }
    return getDefaultCallingConvention();
}

bool BasicCompilerSpec::isGlobal(const Address& addr) const {
    return globalSet_.contains(addr);
}

void BasicCompilerSpec::restoreXml(XmlPullParser& parser) {
    (void)parser;
    // Stub: full .cspec XML parsing not yet ported
}

} // namespace ghidra
