/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/LabelHistory.h"

namespace ghidra {

LabelHistory::LabelHistory(const Address& addr, const std::string& userName,
                           int8_t actionID, const std::string& labelStr,
                           int64_t modificationDate)
    : addr_(addr), userName_(userName), labelStr_(labelStr),
      actionID_(actionID), modificationDate_(modificationDate) {}

} // namespace ghidra
