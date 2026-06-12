#pragma once
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/CommentType.h>
#include <ghidra/ProgramDB.h>
#include "changeset_generated.h"
#include <memory>
#include <string>
#include <vector>

namespace ghidra {
namespace storage {

namespace fb = fbschema;

class Event {
public:
    virtual ~Event() = default;
    virtual void undo(ProgramDB& program) = 0;
    virtual void redo(ProgramDB& program) = 0;
    fb::ChangeType getType() const { return type_; }
    uint64_t getAddress() const { return addr_; }
    const std::string& getName() const { return name_; }
    virtual std::string getOldValue() const { return ""; }
    virtual std::string getNewValue() const { return ""; }
    virtual std::string getChangeSetName() const { return name_; }
protected:
    Event(fb::ChangeType type, uint64_t addr, const std::string& name)
        : type_(type), addr_(addr), name_(name) {}
    fb::ChangeType type_;
    uint64_t addr_;
    std::string name_;
};

class RenameFunctionEvent : public Event {
public:
    RenameFunctionEvent(uint64_t addr, const std::string& oldName, const std::string& newName)
        : Event(fb::ChangeType_RENAME_FUNCTION, addr, ""), oldName_(oldName), newName_(newName) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return oldName_; }
    std::string getNewValue() const override { return newName_; }
private:
    std::string oldName_;
    std::string newName_;
};

class RenameSymbolEvent : public Event {
public:
    RenameSymbolEvent(uint64_t addr, const std::string& oldName, const std::string& newName)
        : Event(fb::ChangeType_RENAME_SYMBOL, addr, ""), oldName_(oldName), newName_(newName) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return oldName_; }
    std::string getNewValue() const override { return newName_; }
private:
    std::string oldName_;
    std::string newName_;
};

class AddSymbolEvent : public Event {
public:
    AddSymbolEvent(uint64_t addr, const std::string& name)
        : Event(fb::ChangeType_ADD_SYMBOL, addr, name) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
};

class RemoveSymbolEvent : public Event {
public:
    RemoveSymbolEvent(uint64_t addr, const std::string& name)
        : Event(fb::ChangeType_REMOVE_SYMBOL, addr, name) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
};

class CreateFunctionEvent : public Event {
public:
    CreateFunctionEvent(uint64_t addr, const std::string& name, const AddressSet& body)
        : Event(fb::ChangeType_CREATE_FUNCTION, addr, name), body_(body) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
private:
    AddressSet body_;
};

class DeleteFunctionEvent : public Event {
public:
    DeleteFunctionEvent(uint64_t addr, const std::string& name, const AddressSet& body)
        : Event(fb::ChangeType_DELETE_FUNCTION, addr, name), body_(body) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
private:
    AddressSet body_;
};

class AddCommentEvent : public Event {
public:
    AddCommentEvent(uint64_t addr, CommentType commentType, const std::string& text)
        : Event(fb::ChangeType_ADD_COMMENT, addr, ""), commentType_(commentType), text_(text) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getNewValue() const override { return text_; }
    std::string getChangeSetName() const override { return commentTypeToString(commentType_); }
private:
    CommentType commentType_;
    std::string text_;
};

class DeleteCommentEvent : public Event {
public:
    DeleteCommentEvent(uint64_t addr, CommentType commentType, const std::string& text)
        : Event(fb::ChangeType_DELETE_COMMENT, addr, ""), commentType_(commentType), text_(text) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return text_; }
    std::string getChangeSetName() const override { return commentTypeToString(commentType_); }
private:
    CommentType commentType_;
    std::string text_;
};

class ModifyCommentEvent : public Event {
public:
    ModifyCommentEvent(uint64_t addr, CommentType commentType,
                       const std::string& oldText, const std::string& newText)
        : Event(fb::ChangeType_MODIFY_COMMENT, addr, ""),
          commentType_(commentType), oldText_(oldText), newText_(newText) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return oldText_; }
    std::string getNewValue() const override { return newText_; }
    std::string getChangeSetName() const override { return commentTypeToString(commentType_); }
private:
    CommentType commentType_;
    std::string oldText_;
    std::string newText_;
};

class AddBookmarkEvent : public Event {
public:
    AddBookmarkEvent(uint64_t addr, const std::string& type, const std::string& text)
        : Event(fb::ChangeType_ADD_BOOKMARK, addr, ""), type_(type), text_(text) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getNewValue() const override { return text_; }
    std::string getChangeSetName() const override { return type_; }
private:
    std::string type_;
    std::string text_;
};

class DeleteBookmarkEvent : public Event {
public:
    DeleteBookmarkEvent(uint64_t addr, const std::string& type, const std::string& text)
        : Event(fb::ChangeType_DELETE_BOOKMARK, addr, ""), type_(type), text_(text) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return text_; }
    std::string getChangeSetName() const override { return type_; }
private:
    std::string type_;
    std::string text_;
};

class CreateDataTypeEvent : public Event {
public:
    CreateDataTypeEvent(const std::string& name, const CategoryPath& categoryPath,
                        int size, int typeKind)
        : Event(fb::ChangeType_CREATE_DATA_TYPE, 0, name),
          categoryPath_(categoryPath), size_(size), typeKind_(typeKind) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getNewValue() const override {
        return std::to_string(size_) + ":" + std::to_string(typeKind_);
    }
private:
    CategoryPath categoryPath_;
    int size_;
    int typeKind_;
};

class DeleteDataTypeEvent : public Event {
public:
    DeleteDataTypeEvent(const std::string& name, const CategoryPath& categoryPath,
                        int size, int typeKind)
        : Event(fb::ChangeType_DELETE_DATA_TYPE, 0, name),
          categoryPath_(categoryPath), size_(size), typeKind_(typeKind) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override {
        return std::to_string(size_) + ":" + std::to_string(typeKind_);
    }
private:
    CategoryPath categoryPath_;
    int size_;
    int typeKind_;
};

class SetFunctionSignatureEvent : public Event {
public:
    SetFunctionSignatureEvent(uint64_t addr, const std::string& funcName,
                              const std::string& sigStr)
        : Event(fb::ChangeType_SET_FUNCTION_SIGNATURE, addr, funcName),
          sigStr_(sigStr) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getNewValue() const override { return sigStr_; }
    std::string getChangeSetName() const override { return "function_signature"; }
private:
    std::string sigStr_;
};

class SetReturnTypeEvent : public Event {
public:
    SetReturnTypeEvent(uint64_t addr, const std::string& funcName,
                       const std::string& oldType, const std::string& newType)
        : Event(fb::ChangeType_SET_RETURN_TYPE, addr, funcName),
          oldType_(oldType), newType_(newType) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return oldType_; }
    std::string getNewValue() const override { return newType_; }
    std::string getChangeSetName() const override { return "return_type"; }
private:
    std::string oldType_;
    std::string newType_;
};

class SetCallingConventionEvent : public Event {
public:
    SetCallingConventionEvent(uint64_t addr, const std::string& funcName,
                              const std::string& oldCc, const std::string& newCc)
        : Event(fb::ChangeType_SET_CALLING_CONVENTION, addr, funcName),
          oldCc_(oldCc), newCc_(newCc) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return oldCc_; }
    std::string getNewValue() const override { return newCc_; }
    std::string getChangeSetName() const override { return "calling_convention"; }
private:
    std::string oldCc_;
    std::string newCc_;
};

class AddParameterEvent : public Event {
public:
    AddParameterEvent(uint64_t addr, const std::string& funcName,
                      const std::string& paramName, const std::string& typeName)
        : Event(fb::ChangeType_ADD_PARAMETER, addr, funcName),
          paramName_(paramName), typeName_(typeName) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getNewValue() const override { return typeName_ + " " + paramName_; }
    std::string getChangeSetName() const override { return "parameter_" + paramName_; }
private:
    std::string paramName_;
    std::string typeName_;
};

class RemoveParameterEvent : public Event {
public:
    RemoveParameterEvent(uint64_t addr, const std::string& funcName,
                         const std::string& paramName, const std::string& typeName)
        : Event(fb::ChangeType_REMOVE_PARAMETER, addr, funcName),
          paramName_(paramName), typeName_(typeName) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return typeName_ + " " + paramName_; }
    std::string getChangeSetName() const override { return "parameter_removed"; }
private:
    std::string paramName_;
    std::string typeName_;
};

class SetNoReturnEvent : public Event {
public:
    SetNoReturnEvent(uint64_t addr, const std::string& funcName, bool oldVal, bool newVal)
        : Event(fb::ChangeType_SET_NO_RETURN, addr, funcName),
          oldVal_(oldVal), newVal_(newVal) {}
    void undo(ProgramDB& program) override;
    void redo(ProgramDB& program) override;
    std::string getOldValue() const override { return oldVal_ ? "true" : "false"; }
    std::string getNewValue() const override { return newVal_ ? "true" : "false"; }
    std::string getChangeSetName() const override { return "noreturn"; }
private:
    bool oldVal_;
    bool newVal_;
};

} // namespace storage
} // namespace ghidra
