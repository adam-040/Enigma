/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/InjectContext.h"
#include "ghidra/AddressXML.h"

namespace ghidra {

void InjectContext::decode(Decoder& decoder) {
    int el = decoder.openElement(ELEM_CONTEXT);
    (void)el;
    // Stub: full AddressXML::decode not yet ported
    decoder.closeElement(el);
}

} // namespace ghidra
