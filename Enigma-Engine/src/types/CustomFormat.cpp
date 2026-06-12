/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/CustomFormat.h>

namespace ghidra {

CustomFormat::CustomFormat(DataType* dt, const std::vector<uint8_t>& fmt)
    : dataType_(dt), format_(fmt) {}

} // namespace ghidra
