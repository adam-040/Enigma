#include "ghidra/patch/MetadataPatch.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/Listing.h"
#include "ghidra/CodeUnit.h"
#include "ghidra/BookmarkManager.h"
#include "ghidra/Address.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace ghidra::patch {

// ── FunctionCreatePatch ──────────────────────────────────────────────

FunctionCreatePatch::FunctionCreatePatch(uint64_t entryAddress, uint64_t bodyStart,
                                         uint64_t bodyEnd,
                                         const std::string& funcName,
                                         std::string patchName,
                                         std::string patchDescription)
    : id_(PatchId::create())
    , entryAddress_(entryAddress)
    , bodyStart_(bodyStart)
    , bodyEnd_(bodyEnd)
    , funcName_(funcName)
    , description_(std::move(patchDescription))
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << "Create function " << funcName << " @ 0x" << std::hex << entryAddress;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

bool FunctionCreatePatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address entryAddr(ramSpace, static_cast<int64_t>(entryAddress_));
    Address bodyAddr(ramSpace, static_cast<int64_t>(bodyStart_));
    Address endAddr(ramSpace, static_cast<int64_t>(bodyEnd_));

    auto* funcMgr = program.getFunctionManager();
    if (!funcMgr) return false;
    AddressSet body(bodyAddr, endAddr);
    return funcMgr->createFunction(funcName_, entryAddr, body, SourceType::USER_DEFINED) != nullptr;
}

bool FunctionCreatePatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address entryAddr(ramSpace, static_cast<int64_t>(entryAddress_));
    auto* funcMgr = program.getFunctionManager();
    if (!funcMgr) return false;
    return funcMgr->removeFunction(entryAddr);
}

std::string FunctionCreatePatch::previewText() const {
    std::ostringstream oss;
    oss << "Create function " << funcName_ << " @ 0x" << std::hex << entryAddress_
        << " (body: 0x" << bodyStart_ << "-0x" << bodyEnd_ << ")";
    return oss.str();
}

// ── FunctionDeletePatch ──────────────────────────────────────────────

FunctionDeletePatch::FunctionDeletePatch(uint64_t entryAddress,
                                         const std::string& funcName,
                                         std::string patchName)
    : id_(PatchId::create())
    , entryAddress_(entryAddress)
    , funcName_(funcName)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << "Delete function " << funcName << " @ 0x" << std::hex << entryAddress;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

bool FunctionDeletePatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address entryAddr(ramSpace, static_cast<int64_t>(entryAddress_));
    auto* funcMgr = program.getFunctionManager();
    if (!funcMgr) return false;
    return funcMgr->removeFunction(entryAddr);
}

bool FunctionDeletePatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address entryAddr(ramSpace, static_cast<int64_t>(entryAddress_));
    Address bodyAddr(ramSpace, static_cast<int64_t>(entryAddress_));
    AddressSet body(bodyAddr, bodyAddr);

    auto* funcMgr = program.getFunctionManager();
    if (!funcMgr) return false;
    return funcMgr->createFunction(funcName_, entryAddr, body, SourceType::USER_DEFINED) != nullptr;
}

std::string FunctionDeletePatch::previewText() const {
    std::ostringstream oss;
    oss << "Delete function " << funcName_ << " @ 0x" << std::hex << entryAddress_;
    return oss.str();
}

// ── FunctionRenamePatch ──────────────────────────────────────────────

FunctionRenamePatch::FunctionRenamePatch(uint64_t entryAddress,
                                         const std::string& oldName,
                                         const std::string& newName,
                                         std::string patchName)
    : id_(PatchId::create())
    , entryAddress_(entryAddress)
    , oldName_(oldName)
    , newName_(newName)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << "Rename function " << oldName << " -> " << newName;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

std::string FunctionRenamePatch::description() const {
    std::ostringstream oss;
    oss << "Rename function @" << std::hex << entryAddress_
        << ": \"" << oldName_ << "\" -> \"" << newName_ << "\"";
    return oss.str();
}

bool FunctionRenamePatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(entryAddress_));
    auto* funcMgr = program.getFunctionManager();
    if (!funcMgr) return false;
    auto* func = funcMgr->getFunctionAt(addr);
    if (!func) return false;
    func->setName(newName_);
    return true;
}

bool FunctionRenamePatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(entryAddress_));
    auto* funcMgr = program.getFunctionManager();
    if (!funcMgr) return false;
    auto* func = funcMgr->getFunctionAt(addr);
    if (!func) return false;
    func->setName(oldName_);
    return true;
}

std::string FunctionRenamePatch::previewText() const {
    std::ostringstream oss;
    oss << "Rename: \"" << oldName_ << "\" -> \"" << newName_ << "\"";
    return oss.str();
}

// ── SymbolCreatePatch ────────────────────────────────────────────────

SymbolCreatePatch::SymbolCreatePatch(uint64_t address,
                                     const std::string& symbolName,
                                     std::string patchName)
    : id_(PatchId::create())
    , address_(address)
    , symbolName_(symbolName)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << "Create label " << symbolName << " @ 0x" << std::hex << address;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

std::string SymbolCreatePatch::description() const {
    std::ostringstream oss;
    oss << "Label \"" << symbolName_ << "\" @ 0x" << std::hex << address_;
    return oss.str();
}

bool SymbolCreatePatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* symTable = program.getSymbolTable();
    if (!symTable) return false;
    return symTable->createLabel(addr, symbolName_, SourceType::USER_DEFINED) != nullptr;
}

bool SymbolCreatePatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* symTable = program.getSymbolTable();
    if (!symTable) return false;
    auto symbols = symTable->getSymbols(addr);
    for (auto* sym : symbols) {
        if (sym && sym->getName() == symbolName_) {
            symTable->removeSymbolSpecial(sym);
            return true;
        }
    }
    return false;
}

std::string SymbolCreatePatch::previewText() const {
    std::ostringstream oss;
    oss << "Create label \"" << symbolName_ << "\" @ 0x" << std::hex << address_;
    return oss.str();
}

// ── SymbolRenamePatch ────────────────────────────────────────────────

SymbolRenamePatch::SymbolRenamePatch(uint64_t address,
                                     const std::string& oldName,
                                     const std::string& newName,
                                     std::string patchName)
    : id_(PatchId::create())
    , address_(address)
    , oldName_(oldName)
    , newName_(newName)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << "Rename label " << oldName << " -> " << newName;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

std::string SymbolRenamePatch::description() const {
    std::ostringstream oss;
    oss << "Rename label @" << std::hex << address_
        << ": \"" << oldName_ << "\" -> \"" << newName_ << "\"";
    return oss.str();
}

bool SymbolRenamePatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* symTable = program.getSymbolTable();
    if (!symTable) return false;
    auto symbols = symTable->getSymbols(addr);
    for (auto* sym : symbols) {
        if (sym && sym->getName() == oldName_) {
            sym->setName(newName_);
            return true;
        }
    }
    return false;
}

bool SymbolRenamePatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* symTable = program.getSymbolTable();
    if (!symTable) return false;
    auto symbols = symTable->getSymbols(addr);
    for (auto* sym : symbols) {
        if (sym && sym->getName() == newName_) {
            sym->setName(oldName_);
            return true;
        }
    }
    return false;
}

std::string SymbolRenamePatch::previewText() const {
    std::ostringstream oss;
    oss << "Rename label: \"" << oldName_ << "\" -> \"" << newName_ << "\"";
    return oss.str();
}

// ── SymbolDeletePatch ────────────────────────────────────────────────

SymbolDeletePatch::SymbolDeletePatch(uint64_t address,
                                     const std::string& symbolName,
                                     std::string patchName)
    : id_(PatchId::create())
    , address_(address)
    , symbolName_(symbolName)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << "Delete label " << symbolName << " @ 0x" << std::hex << address;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

std::string SymbolDeletePatch::description() const {
    std::ostringstream oss;
    oss << "Delete label \"" << symbolName_ << "\" @ 0x" << std::hex << address_;
    return oss.str();
}

bool SymbolDeletePatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* symTable = program.getSymbolTable();
    if (!symTable) return false;
    auto symbols = symTable->getSymbols(addr);
    for (auto* sym : symbols) {
        if (sym && sym->getName() == symbolName_) {
            symTable->removeSymbolSpecial(sym);
            return true;
        }
    }
    return false;
}

bool SymbolDeletePatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* symTable = program.getSymbolTable();
    if (!symTable) return false;
    return symTable->createLabel(addr, symbolName_, SourceType::USER_DEFINED) != nullptr;
}

std::string SymbolDeletePatch::previewText() const {
    std::ostringstream oss;
    oss << "Delete label \"" << symbolName_ << "\" @ 0x" << std::hex << address_;
    return oss.str();
}

// ── CommentPatch ─────────────────────────────────────────────────────

CommentPatch::CommentPatch(uint64_t address,
                           CommentType commentType,
                           const std::string& oldText,
                           const std::string& newText,
                           std::string patchName)
    : id_(PatchId::create())
    , address_(address)
    , commentType_(commentType)
    , oldText_(oldText)
    , newText_(newText)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << ((newText.empty()) ? "Remove" : "Set") << " comment @ 0x" << std::hex << address;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

PatchCategory CommentPatch::categoryFor(CommentType t, const std::string& newText) {
    if (newText.empty()) return PatchCategory::COMMENT_DELETE;
    if (t == CommentType::EOL) return PatchCategory::COMMENT_ADD;
    return PatchCategory::COMMENT_MODIFY;
}

PatchCategory CommentPatch::category() const {
    return categoryFor(commentType_, newText_);
}

std::string CommentPatch::description() const {
    std::ostringstream oss;
    oss << "Comment @" << std::hex << address_ << ": \""
        << oldText_ << "\" -> \"" << newText_ << "\"";
    return oss.str();
}

bool CommentPatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* listing = program.getListing();
    if (!listing) return false;
    auto* codeUnit = listing->getCodeUnitAt(addr);
    if (!codeUnit) return false;

    switch (commentType_) {
    case CommentPatch::CommentType::EOL: codeUnit->setComment(newText_); break;
    case CommentPatch::CommentType::PRE: codeUnit->setPreComment(newText_); break;
    case CommentPatch::CommentType::POST: codeUnit->setPostComment(newText_); break;
    case CommentPatch::CommentType::PLATE: codeUnit->setPlateComment(newText_); break;
    case CommentPatch::CommentType::REPEATABLE: codeUnit->setComment(newText_); break;
    }
    return true;
}

bool CommentPatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* listing = program.getListing();
    if (!listing) return false;
    auto* codeUnit = listing->getCodeUnitAt(addr);
    if (!codeUnit) return false;

    switch (commentType_) {
    case CommentPatch::CommentType::EOL: codeUnit->setComment(oldText_); break;
    case CommentPatch::CommentType::PRE: codeUnit->setPreComment(oldText_); break;
    case CommentPatch::CommentType::POST: codeUnit->setPostComment(oldText_); break;
    case CommentPatch::CommentType::PLATE: codeUnit->setPlateComment(oldText_); break;
    case CommentPatch::CommentType::REPEATABLE: codeUnit->setComment(oldText_); break;
    }

    return true;
}

std::string CommentPatch::previewText() const {
    std::ostringstream oss;
    oss << "Comment @" << std::hex << address_ << ": \""
        << oldText_ << "\" -> \"" << newText_ << "\"";
    return oss.str();
}

// ── BookmarkPatch ────────────────────────────────────────────────────

BookmarkPatch::BookmarkPatch(uint64_t address,
                             const std::string& comment,
                             bool isAdd,
                             std::string patchName)
    : id_(PatchId::create())
    , address_(address)
    , comment_(comment)
    , isAdd_(isAdd)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << (isAdd ? "Add" : "Delete") << " bookmark @ 0x" << std::hex << address;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

std::string BookmarkPatch::description() const {
    std::ostringstream oss;
    oss << (isAdd_ ? "Add" : "Delete") << " bookmark @ 0x" << std::hex << address_
        << ": \"" << comment_ << "\"";
    return oss.str();
}

bool BookmarkPatch::apply(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* bmMgr = program.getBookmarkManager();
    if (!bmMgr) return false;

    if (isAdd_) {
        bmMgr->setBookmark(addr, "Note", comment_);
    } else {
        bmMgr->removeBookmark(addr, "Note");
    }
    return true;
}

bool BookmarkPatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    auto* addrFactory = program.getAddressFactory();
    if (!addrFactory) return false;
    auto* ramSpace = const_cast<AddressSpace*>(addrFactory->getAddressSpace("ram"));
    if (!ramSpace) return false;

    Address addr(ramSpace, static_cast<int64_t>(address_));
    auto* bmMgr = program.getBookmarkManager();
    if (!bmMgr) return false;

    if (isAdd_) {
        bmMgr->removeBookmark(addr, "Note");
    } else {
        bmMgr->setBookmark(addr, "Note", comment_);
    }
    return true;
}

std::string BookmarkPatch::previewText() const {
    std::ostringstream oss;
    oss << (isAdd_ ? "Add" : "Delete") << " bookmark @ 0x" << std::hex << address_;
    return oss.str();
}

} // namespace ghidra::patch
