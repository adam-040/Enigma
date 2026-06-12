/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/DatatypeFilter.h>
#include <ghidra/SizeRestrictedFilter.h>
#include <ghidra/MetaTypeFilter.h>
#include <ghidra/HomogeneousAggregate.h>
#include <ghidra/Metatype.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/AttributeId.h>

namespace ghidra {

DatatypeFilter* DatatypeFilter::restoreFilterXml(XmlPullParser& parser) {
    DatatypeFilter* filter = nullptr;
    XmlElement elem = parser.peek();
    std::string nm = elem.getAttribute(ATTRIB_NAME.name);
    if (nm == SizeRestrictedFilter::NAME) {
        filter = new SizeRestrictedFilter();
    } else if (nm == HomogeneousAggregate::NAME_FLOAT) {
        filter = new HomogeneousAggregate(HomogeneousAggregate::NAME_FLOAT,
            Metatype::TYPE_FLOAT, HomogeneousAggregate::DEFAULT_MAX_PRIMITIVES, 0, 0);
    } else {
        int meta = Metatype::getMetatypeFromString(nm);
        filter = new MetaTypeFilter(meta);
    }
    filter->restoreXml(parser);
    return filter;
}

} // namespace ghidra
