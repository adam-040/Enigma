/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/SimpleBlockIterator.h>
#include <ghidra/block/SimpleBlockModel.h>

namespace ghidra {

SimpleBlockIterator::SimpleBlockIterator(SimpleBlockModel* model,
                                         const std::vector<CodeBlock*>& blocks)
    : CodeBlockIterator(blocks) {
    (void)model;
}

} // namespace ghidra
