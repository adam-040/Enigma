/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LabelHistory.h
/// \brief Container for label history information
/// Translated from: ghidra.program.model.symbol.LabelHistory
#pragma once

#include <ghidra/Address.h>
#include <string>
#include <cstdint>

namespace ghidra {

class LabelHistory {
public:
    static constexpr int8_t ADD = 0;
    static constexpr int8_t REMOVE = 1;
    static constexpr int8_t RENAME = 2;

    LabelHistory() = default;
    LabelHistory(const Address& addr, const std::string& userName,
                 int8_t actionID, const std::string& labelStr,
                 int64_t modificationDate);

    const Address& getAddress() const { return addr_; }
    const std::string& getUserName() const { return userName_; }
    const std::string& getLabelString() const { return labelStr_; }
    int8_t getActionID() const { return actionID_; }
    int64_t getModificationDate() const { return modificationDate_; }

private:
    Address addr_;
    std::string userName_;
    std::string labelStr_;
    int8_t actionID_ = ADD;
    int64_t modificationDate_ = 0;
};

} // namespace ghidra
