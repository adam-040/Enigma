#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <functional>

namespace ghidra {

class Address;
class Memory;
class ProgramDB;
class FunctionManager;
class SymbolTable;
class BookmarkManager;

namespace patch {

enum class PatchCategory {
    BYTE,
    NOP_FILL,
    INSTRUCTION,
    STRING,
    FUNCTION_CREATE,
    FUNCTION_DELETE,
    FUNCTION_RENAME,
    FUNCTION_BOUNDARY,
    SYMBOL_CREATE,
    SYMBOL_RENAME,
    SYMBOL_DELETE,
    COMMENT_ADD,
    COMMENT_MODIFY,
    COMMENT_DELETE,
    BOOKMARK_ADD,
    BOOKMARK_DELETE,
    IMPORT_ADD,
    IMPORT_REMOVE,
    EXPORT_ADD,
    EXPORT_REMOVE,
    SECTION_ADD,
    SECTION_REMOVE,
    SECTION_RESIZE,
    SECTION_PERMISSIONS,
    HEADER_MODIFY,
    ENTRY_POINT_CHANGE,
    IMAGE_BASE_CHANGE,
    CHECKSUM_FIX
};

struct PatchId {
    std::string id;
    static PatchId create();
    explicit operator bool() const { return !id.empty(); }
};

class Patch {
public:
    virtual ~Patch() = default;

    virtual PatchId id() const = 0;
    virtual PatchCategory category() const = 0;
    virtual std::string name() const = 0;
    virtual std::string description() const = 0;

    virtual bool apply(Memory& memory, ProgramDB& program) = 0;
    virtual bool revert(Memory& memory, ProgramDB& program) = 0;

    virtual std::string previewText() const = 0;
    virtual std::vector<uint8_t> originalBytes() const;
    virtual std::vector<uint8_t> patchedBytes() const;

    virtual uint64_t baseAddress() const;
    virtual uint64_t size() const;
    virtual std::vector<uint64_t> affectedAddresses() const;

    // For multi-site patches (e.g., trampolines): additional {address, bytes} pairs
    // that should be written alongside the primary patchedBytes at baseAddress().
    virtual std::vector<std::pair<uint64_t, std::vector<uint8_t>>> additionalWrites() const {
        return {};
    }

    // For relocation: {VA where 8-byte absolute value sits, the absolute value}
    // Only InstructionPatch with64-bit absolute immediates returns non-empty.
    virtual std::vector<std::pair<uint64_t, uint64_t>> getRelocationEntries() const {
        return {};
    }

    std::string groupId() const { return groupId_; }
    void setGroupId(const std::string& gid) { groupId_ = gid; }

    bool enabled() const { return enabled_; }
    void setEnabled(bool e) { enabled_ = e; }

    bool applied() const { return applied_; }
    void setApplied(bool a) { applied_ = a; }

    std::chrono::system_clock::time_point createdAt() const { return createdAt_; }

    virtual bool conflictsWith(const Patch& other) const;

protected:
    Patch();

    std::string groupId_;
    bool enabled_ = true;
    bool applied_ = false;
    std::chrono::system_clock::time_point createdAt_;
};

} // namespace patch
} // namespace ghidra
