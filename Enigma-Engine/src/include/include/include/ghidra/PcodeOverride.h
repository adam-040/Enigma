/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PcodeOverride.h
/// \brief Per-instruction overrides applied during pcode generation.
/// Translated from: ghidra.program.model.pcode.PcodeOverride
#pragma once

namespace ghidra {

class Address;
class RefType;
enum class FlowOverride : int;
class InjectPayload;
class PcodeInject;

/**
 * PcodeOverride: per-instruction hook for flow-override, call-fixup, and
 * reference-override behavior. Implementations are supplied by the
 * decompiler infrastructure for each analyzed instruction.
 *
 * The signatures here match the existing InstructionPcodeOverride
 * implementation: by-value Address/FlowOverride returns, const& Address
 * parameters.
 */
class PcodeOverride {
public:
    virtual ~PcodeOverride() = default;

    virtual Address getInstructionStart() = 0;
    virtual FlowOverride getFlowOverride() = 0;
    virtual Address getOverridingReference(const RefType* type) = 0;
    virtual Address getFallThroughOverride() = 0;

    virtual bool hasCallFixup(const Address& callDestAddr) = 0;
    virtual PcodeInject* getCallFixup(const Address& callDestAddr) = 0;

    virtual void setCallOverrideRefApplied() = 0;
    virtual bool isCallOverrideRefApplied() = 0;

    virtual void setJumpOverrideRefApplied() = 0;
    virtual bool isJumpOverrideRefApplied() = 0;

    virtual void setCallOtherCallOverrideRefApplied() = 0;
    virtual bool isCallOtherCallOverrideRefApplied() = 0;

    virtual void setCallOtherJumpOverrideRefApplied() = 0;
    virtual bool isCallOtherJumpOverrideApplied() = 0;

    virtual bool hasPotentialOverride() = 0;
    virtual Address getPrimaryCallReference() = 0;
};

}  // namespace ghidra
