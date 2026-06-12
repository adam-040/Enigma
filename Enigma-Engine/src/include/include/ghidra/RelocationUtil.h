/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationUtil.h
/// \brief Utility for finding relocation handlers.
#pragma once

#include "ghidra/RelocationHandler.h"
#include <vector>

namespace ghidra {

class RelocationUtil {
public:
    static std::vector<RelocationHandler*> getRelocationHandlers();
    static void registerHandler(RelocationHandler* handler);
};

} // namespace ghidra
