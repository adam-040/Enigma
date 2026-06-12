/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/QualifierFilter.h>
#include <ghidra/PositionMatchFilter.h>
#include <ghidra/VarargsFilter.h>
#include <ghidra/DatatypeMatchFilter.h>
#include <ghidra/ElementId.h>
#include <ghidra/XmlPullParser.h>

namespace ghidra {

QualifierFilter* QualifierFilter::restoreFilterXml(class XmlPullParser& parser) {
    if (!parser.hasNext()) return nullptr;
    XmlElement elem = parser.nextElement();
    const std::string& name = elem.getName();

    if (name == ELEM_POSITION.name) {
        auto* filter = new PositionMatchFilter(0);
        return filter;
    }
    if (name == ELEM_VARARGS.name) {
        auto* filter = new VarargsFilter();
        return filter;
    }
    if (name == ELEM_DATATYPE_AT.name) {
        auto* filter = new DatatypeMatchFilter();
        return filter;
    }
    return nullptr;
}

} // namespace ghidra
