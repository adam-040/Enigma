#pragma once

#include "ghidra/Memory.h"
#include <map>
#include <functional>
#include <mutex>

namespace ghidra::patch {

class PatchMemory : public Memory {
public:
    explicit PatchMemory(std::unique_ptr<Memory> original);

    // Override getters — check overlay first, fall back to original
    bool isBigEndian() const override;
    long long getSize() const override;
    MemoryBlock* getBlock(const Address& addr) override;
    MemoryBlock* getBlock(const std::string& blockName) override;
    std::vector<MemoryBlock*> getBlocks() override;

    uint8_t getByte(const Address& addr) override;
    int getBytes(const Address& addr, uint8_t* dest, int size) override;
    uint16_t getShort(const Address& addr) override;
    uint16_t getShort(const Address& addr, bool bigEndian) override;
    uint32_t getInt(const Address& addr) override;
    uint32_t getInt(const Address& addr, bool bigEndian) override;
    uint64_t getLong(const Address& addr) override;
    uint64_t getLong(const Address& addr, bool bigEndian) override;

    // set overrides — forbidden; use PatchManager instead
    void setByte(const Address& addr, uint8_t value) override;
    void setBytes(const Address& addr, const uint8_t* source, int size) override;
    void setShort(const Address& addr, uint16_t value) override;
    void setShort(const Address& addr, uint16_t value, bool bigEndian) override;
    void setInt(const Address& addr, uint32_t value) override;
    void setInt(const Address& addr, uint32_t value, bool bigEndian) override;
    void setLong(const Address& addr, uint64_t value) override;
    void setLong(const Address& addr, uint64_t value, bool bigEndian) override;

    // Overlay management — called by PatchManager
    void applyPatch(const std::vector<uint8_t>& bytes, uint64_t address);
    void removePatch(uint64_t address, uint64_t size);
    bool hasOverride(uint64_t address) const;
    bool hasOverrideRange(uint64_t address, uint64_t size) const;
    void clearOverrides();

    // Callback — set by GUI layer for live view updates
    using BytesChangedCallback = std::function<void(uint64_t address, uint64_t size)>;
    void setOnBytesChanged(BytesChangedCallback cb) { onBytesChanged_ = std::move(cb); }

private:
    std::unique_ptr<Memory> original_;
    std::map<uint64_t, uint8_t> overlay_;
    mutable std::mutex mutex_;
    BytesChangedCallback onBytesChanged_;

    void emitBytesChanged(uint64_t address, uint64_t size);
};

} // namespace ghidra::patch
