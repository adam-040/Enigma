/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CachedEncoder.h
/// \brief Encoder that buffers bytes in memory for later flush to OutputStream.
/// Translated from: ghidra.program.model.pcode.CachedEncoder
#pragma once

#include "ghidra/Encoder.h"
#include <vector>
#include <iosfwd>

namespace ghidra {

/// Interface for an Encoder that buffers output in memory until writeTo() is called.
class CachedEncoder : public Encoder {
public:
    virtual ~CachedEncoder() = default;

    /// Clear all buffered state, ready for a new document.
    virtual void clear() = 0;

    /// True if no bytes are buffered.
    virtual bool isEmpty() const = 0;

    /// Dump all buffered bytes to the given output stream.
    virtual void writeTo(std::ostream& stream) = 0;
};

/// In-memory CachedEncoder backed by a std::vector<uint8_t>.
class MemoryCachedEncoder : public CachedEncoder {
public:
    void clear() override { buffer.clear(); depthStack.clear(); }
    bool isEmpty() const override { return buffer.empty(); }
    void writeTo(std::ostream& stream) override;
    const std::vector<uint8_t>& getBuffer() const { return buffer; }

    void openElement(const ElementId& elemId) override;
    void closeElement(const ElementId& elemId) override;
    void writeBool(const AttributeId& attribId, bool val) override;
    void writeSignedInteger(const AttributeId& attribId, int64_t val) override;
    void writeUnsignedInteger(const AttributeId& attribId, uint64_t val) override;
    void writeString(const AttributeId& attribId, const std::string& val) override;
    void writeSpace(const AttributeId& attribId, const AddressSpace* spc) override;

private:
    std::vector<uint8_t> buffer;
    std::vector<int> depthStack;
};

} // namespace ghidra
