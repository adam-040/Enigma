/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/PackedEncodeOverlay.h>

namespace ghidra {

void PackedEncodeOverlay::writeSpace(const AttributeId& attribId, const AddressSpace* spc) {
    int64_t spaceId = spc ? spc->getSpaceID() : -1;
    writeSignedInteger(attribId, spaceId);
}

void PackedEncodeOverlay::writeSpace(const AttributeId& attribId, int index, const std::string& name) {
    writeString(attribId, name);
}

} // namespace ghidra
