/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramContextImpl.h
/// \brief Implementation of program context for register values
/// Translated from: ghidra.program.database.register.ProgramRegisterContextDB
#pragma once

#include <ghidra/ProgramContext.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/AddressRangeImpl.h>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <memory>

namespace ghidra {

class ProgramContextImpl : public ProgramContext {
public:
    ProgramContextImpl() = default;
    explicit ProgramContextImpl(Register* contextReg) : contextRegister_(contextReg) {}

    void setValue(Register* reg, uint64_t value, const Address& start, const Address& end) override;

    void setRegisterValue(RegisterValue* value, const Address& start, const Address& end) override;

    void clearRegister(Register* reg, const Address& start, const Address& end) override;

    uint64_t getValue(Register* reg, const Address& address) const override;

    RegisterValue* getRegisterValue(Register* reg, const Address& address) const override;

    Register* getContextRegister() const override { return contextRegister_; }
    void setContextRegister(Register* reg) override { contextRegister_ = reg; }

    void setDefaultValue(RegisterValue* value, const Address& start, const Address& end);

    RegisterValue* getDefaultValue(Register* reg, const Address& address) const;

    void clearAll();

    /** Takes ownership of a register referenced by stored context values. */
    Register* addOwnedRegister(std::unique_ptr<Register> reg) {
        Register* raw = reg.get();
        ownedRegisters_.push_back(std::move(reg));
        return raw;
    }

    struct RangeKey {
        Register* reg;
        Address start;
        Address end;

        RangeKey(Register* r, const Address& s, const Address& e)
            : reg(r), start(s), end(e) {}

        bool operator==(const RangeKey& other) const {
            return reg == other.reg && start == other.start && end == other.end;
        }
    };

    struct RangeKeyHash {
        size_t operator()(const RangeKey& k) const {
            return std::hash<void*>{}(k.reg) ^ std::hash<std::string>{}(k.start.toString()) ^
                   std::hash<std::string>{}(k.end.toString());
        }
    };

    const std::unordered_map<RangeKey, uint64_t, RangeKeyHash>& getUint64Values() const { return uint64Values_; }
    const std::unordered_map<RangeKey, RegisterValue*, RangeKeyHash>& getRegisterValues() const { return regValues_; }
    const std::unordered_map<RangeKey, RegisterValue*, RangeKeyHash>& getDefaultValues() const { return defaultValues_; }

private:
    Register* contextRegister_ = nullptr;
    std::unordered_map<RangeKey, uint64_t, RangeKeyHash> uint64Values_;
    std::unordered_map<RangeKey, RegisterValue*, RangeKeyHash> regValues_;
    std::unordered_map<RangeKey, RegisterValue*, RangeKeyHash> defaultValues_;
    std::vector<std::unique_ptr<RegisterValue>> ownedRegisterValues_;
    std::vector<std::unique_ptr<Register>> ownedRegisters_;
};

} // namespace ghidra
