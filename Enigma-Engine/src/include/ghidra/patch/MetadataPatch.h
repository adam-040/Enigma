#pragma once

#include "ghidra/patch/Patch.h"
#include <string>
#include <cstdint>
#include <functional>

namespace ghidra {

class Function;
class Address;

namespace patch {

// ── Function Patches ─────────────────────────────────────────────────

class FunctionCreatePatch : public Patch {
public:
    FunctionCreatePatch(uint64_t entryAddress, uint64_t bodyStart, uint64_t bodyEnd,
                        const std::string& funcName,
                        std::string patchName = "",
                        std::string patchDescription = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::FUNCTION_CREATE; }
    std::string name() const override { return name_; }
    std::string description() const override { return description_; }
    uint64_t baseAddress() const override { return entryAddress_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    PatchId id_;
    uint64_t entryAddress_;
    uint64_t bodyStart_;
    uint64_t bodyEnd_;
    std::string funcName_;
    std::string name_;
    std::string description_;
};

class FunctionDeletePatch : public Patch {
public:
    FunctionDeletePatch(uint64_t entryAddress,
                        const std::string& funcName,
                        std::string patchName = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::FUNCTION_DELETE; }
    std::string name() const override { return name_; }
    std::string description() const override { return description_; }
    uint64_t baseAddress() const override { return entryAddress_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    PatchId id_;
    uint64_t entryAddress_;
    std::string funcName_;
    std::string name_;
    std::string description_;
};

class FunctionRenamePatch : public Patch {
public:
    FunctionRenamePatch(uint64_t entryAddress,
                        const std::string& oldName,
                        const std::string& newName,
                        std::string patchName = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::FUNCTION_RENAME; }
    std::string name() const override { return name_; }
    std::string description() const override;
    uint64_t baseAddress() const override { return entryAddress_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    PatchId id_;
    uint64_t entryAddress_;
    std::string oldName_;
    std::string newName_;
    std::string name_;
};

// ── Symbol Patches ───────────────────────────────────────────────────

class SymbolCreatePatch : public Patch {
public:
    SymbolCreatePatch(uint64_t address,
                      const std::string& symbolName,
                      std::string patchName = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::SYMBOL_CREATE; }
    std::string name() const override { return name_; }
    std::string description() const override;
    uint64_t baseAddress() const override { return address_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    PatchId id_;
    uint64_t address_;
    std::string symbolName_;
    std::string name_;
};

class SymbolRenamePatch : public Patch {
public:
    SymbolRenamePatch(uint64_t address,
                      const std::string& oldName,
                      const std::string& newName,
                      std::string patchName = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::SYMBOL_RENAME; }
    std::string name() const override { return name_; }
    std::string description() const override;
    uint64_t baseAddress() const override { return address_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    PatchId id_;
    uint64_t address_;
    std::string oldName_;
    std::string newName_;
    std::string name_;
};

class SymbolDeletePatch : public Patch {
public:
    SymbolDeletePatch(uint64_t address,
                      const std::string& symbolName,
                      std::string patchName = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::SYMBOL_DELETE; }
    std::string name() const override { return name_; }
    std::string description() const override;
    uint64_t baseAddress() const override { return address_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    PatchId id_;
    uint64_t address_;
    std::string symbolName_;
    std::string name_;
};

// ── Comment Patches ─────────────────────────────────────────────────

class CommentPatch : public Patch {
public:
    enum class CommentType { EOL, PRE, POST, PLATE, REPEATABLE };

    CommentPatch(uint64_t address,
                 CommentType commentType,
                 const std::string& oldText,
                 const std::string& newText,
                 std::string patchName = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override;
    std::string name() const override { return name_; }
    std::string description() const override;
    uint64_t baseAddress() const override { return address_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    static PatchCategory categoryFor(CommentType t, const std::string& newText);
    PatchId id_;
    uint64_t address_;
    CommentType commentType_;
    std::string oldText_;
    std::string newText_;
    std::string name_;
};

// ── Bookmark Patches ────────────────────────────────────────────────

class BookmarkPatch : public Patch {
public:
    BookmarkPatch(uint64_t address,
                  const std::string& comment,
                  bool isAdd,
                  std::string patchName = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override {
        return isAdd_ ? PatchCategory::BOOKMARK_ADD : PatchCategory::BOOKMARK_DELETE;
    }
    std::string name() const override { return name_; }
    std::string description() const override;
    uint64_t baseAddress() const override { return address_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;
    std::string previewText() const override;

private:
    PatchId id_;
    uint64_t address_;
    std::string comment_;
    bool isAdd_;
    std::string name_;
};

} // namespace ghidra::patch
} // namespace ghidra
