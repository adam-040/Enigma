/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

namespace ghidra {

class CodeBlockReference;
class CancelledException;

class CodeBlockReferenceIterator {
public:
    virtual ~CodeBlockReferenceIterator() = default;
    virtual bool hasNext() = 0;
    virtual CodeBlockReference* next() = 0;
};

} // namespace ghidra
