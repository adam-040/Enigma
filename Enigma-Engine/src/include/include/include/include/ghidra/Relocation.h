/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Relocation.h
/// \brief A class to store the information needed for a single program relocation
/// Translated from: ghidra.program.model.reloc.Relocation
#pragma once

#include <ghidra/Address.h>
#include <vector>
#include <string>
#include <stdexcept>

namespace ghidra {

class Relocation {
public:
    enum class Status : int {
        UNKNOWN        = 0,
        SKIPPED        = 1,
        UNSUPPORTED    = 2,
        FAILURE        = 3,
        PARTIAL        = 4,
        APPLIED        = 5,
        APPLIED_OTHER  = 6
    };

    Relocation() = default;

    Relocation(Address addr, Status status, int type, const std::vector<int64_t>& values,
               const std::vector<uint8_t>& bytes, const std::string& symbolName)
        : addr_(addr), status_(status), type_(type),
          values_(values), bytes_(bytes), symbolName_(symbolName) {}

    Relocation(Address addr, int type, const std::string& symbolName)
        : addr_(addr), status_(Status::UNKNOWN), type_(type), symbolName_(symbolName) {}

    Address getAddress() const { return addr_; }
    Status getStatus() const { return status_; }
    int getType() const { return type_; }
    const std::vector<int64_t>& getValues() const { return values_; }
    const std::vector<uint8_t>& getBytes() const { return bytes_; }
    int getLength() const { return static_cast<int>(bytes_.size()); }
    const std::string& getSymbolName() const { return symbolName_; }

    bool hasBytes() const {
        return status_ == Status::APPLIED || status_ == Status::APPLIED_OTHER || status_ == Status::UNKNOWN;
    }

    static Status getStatus(int value) {
        switch (value) {
            case 0: return Status::UNKNOWN;
            case 1: return Status::SKIPPED;
            case 2: return Status::UNSUPPORTED;
            case 3: return Status::FAILURE;
            case 4: return Status::PARTIAL;
            case 5: return Status::APPLIED;
            case 6: return Status::APPLIED_OTHER;
            default: throw std::invalid_argument("Undefined Status value: " + std::to_string(value));
        }
    }

private:
    Address addr_;
    Status status_ = Status::UNKNOWN;
    int type_ = 0;
    std::vector<int64_t> values_;
    std::vector<uint8_t> bytes_;
    std::string symbolName_;
};

} // namespace ghidra
