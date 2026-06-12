#include <ghidra/storage/Event.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionSignatureImpl.h>
#include <ghidra/Listing.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/VariableStorage.h>

namespace ghidra {
namespace storage {

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

static CodeUnit* getCodeUnit(ProgramDB& program, uint64_t addr) {
    Listing* listing = program.getListing();
    if (!listing) return nullptr;
    return listing->getCodeUnitAt(Address(nullptr, addr));
}

static void setCommentOnCodeUnit(CodeUnit* cu, CommentType type, const std::string& text) {
    switch (type) {
    case CommentType::EOL: cu->setComment(text); break;
    case CommentType::PRE: cu->setPreComment(text); break;
    case CommentType::POST: cu->setPostComment(text); break;
    case CommentType::PLATE: cu->setPlateComment(text); break;
    case CommentType::REPEATABLE: break;
    }
}

static DataType* createDataTypeForKind(const std::string& name, const CategoryPath& path,
                                       int size, int typeKind, DataTypeManager* dtm) {
    switch (typeKind) {
    case 0:
        return new StructureDataType(path, name, size, dtm);
    case 1:
        return new EnumDataType(path, name, size, dtm);
    default:
        return new StructureDataType(path, name, size, dtm);
    }
}

// ------------------------------------------------------------------
// RenameFunctionEvent
// ------------------------------------------------------------------

void RenameFunctionEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) func->setName(oldName_);
}

void RenameFunctionEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) func->setName(newName_);
}

// ------------------------------------------------------------------
// RenameSymbolEvent
// ------------------------------------------------------------------

void RenameSymbolEvent::undo(ProgramDB& program) {
    SymbolTable* st = program.getSymbolTable();
    if (!st) return;
    Symbol* sym = st->getPrimarySymbol(Address(nullptr, addr_));
    if (sym) sym->setName(oldName_);
}

void RenameSymbolEvent::redo(ProgramDB& program) {
    SymbolTable* st = program.getSymbolTable();
    if (!st) return;
    Symbol* sym = st->getPrimarySymbol(Address(nullptr, addr_));
    if (sym) sym->setName(newName_);
}

// ------------------------------------------------------------------
// AddSymbolEvent
// ------------------------------------------------------------------

void AddSymbolEvent::undo(ProgramDB& program) {
    SymbolTable* st = program.getSymbolTable();
    if (!st) return;
    std::vector<Symbol*> syms = st->getSymbols(Address(nullptr, addr_));
    for (Symbol* sym : syms) {
        if (sym->getName() == name_) {
            st->removeSymbolSpecial(sym);
            break;
        }
    }
}

void AddSymbolEvent::redo(ProgramDB& program) {
    SymbolTable* st = program.getSymbolTable();
    if (!st) return;
    st->createLabel(Address(nullptr, addr_), name_, SourceType::DEFAULT);
}

// ------------------------------------------------------------------
// RemoveSymbolEvent
// ------------------------------------------------------------------

void RemoveSymbolEvent::undo(ProgramDB& program) {
    SymbolTable* st = program.getSymbolTable();
    if (!st) return;
    st->createLabel(Address(nullptr, addr_), name_, SourceType::DEFAULT);
}

void RemoveSymbolEvent::redo(ProgramDB& program) {
    SymbolTable* st = program.getSymbolTable();
    if (!st) return;
    std::vector<Symbol*> syms = st->getSymbols(Address(nullptr, addr_));
    for (Symbol* sym : syms) {
        if (sym->getName() == name_) {
            st->removeSymbolSpecial(sym);
            break;
        }
    }
}

// ------------------------------------------------------------------
// CreateFunctionEvent
// ------------------------------------------------------------------

void CreateFunctionEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    fm->removeFunction(Address(nullptr, addr_));
}

void CreateFunctionEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    fm->createFunction(name_, Address(nullptr, addr_), body_, SourceType::DEFAULT);
}

// ------------------------------------------------------------------
// DeleteFunctionEvent
// ------------------------------------------------------------------

void DeleteFunctionEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    fm->createFunction(name_, Address(nullptr, addr_), body_, SourceType::DEFAULT);
}

void DeleteFunctionEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    fm->removeFunction(Address(nullptr, addr_));
}

// ------------------------------------------------------------------
// AddCommentEvent
// ------------------------------------------------------------------

void AddCommentEvent::undo(ProgramDB& program) {
    CodeUnit* cu = getCodeUnit(program, addr_);
    if (!cu) return;
    setCommentOnCodeUnit(cu, commentType_, "");
}

void AddCommentEvent::redo(ProgramDB& program) {
    CodeUnit* cu = getCodeUnit(program, addr_);
    if (!cu) return;
    setCommentOnCodeUnit(cu, commentType_, text_);
}

// ------------------------------------------------------------------
// DeleteCommentEvent
// ------------------------------------------------------------------

void DeleteCommentEvent::undo(ProgramDB& program) {
    CodeUnit* cu = getCodeUnit(program, addr_);
    if (!cu) return;
    setCommentOnCodeUnit(cu, commentType_, text_);
}

void DeleteCommentEvent::redo(ProgramDB& program) {
    CodeUnit* cu = getCodeUnit(program, addr_);
    if (!cu) return;
    setCommentOnCodeUnit(cu, commentType_, "");
}

// ------------------------------------------------------------------
// ModifyCommentEvent
// ------------------------------------------------------------------

void ModifyCommentEvent::undo(ProgramDB& program) {
    CodeUnit* cu = getCodeUnit(program, addr_);
    if (!cu) return;
    setCommentOnCodeUnit(cu, commentType_, oldText_);
}

void ModifyCommentEvent::redo(ProgramDB& program) {
    CodeUnit* cu = getCodeUnit(program, addr_);
    if (!cu) return;
    setCommentOnCodeUnit(cu, commentType_, newText_);
}

// ------------------------------------------------------------------
// AddBookmarkEvent
// ------------------------------------------------------------------

void AddBookmarkEvent::undo(ProgramDB& program) {
    BookmarkManager* bm = program.getBookmarkManager();
    if (!bm) return;
    bm->removeBookmark(Address(nullptr, addr_), type_);
}

void AddBookmarkEvent::redo(ProgramDB& program) {
    BookmarkManager* bm = program.getBookmarkManager();
    if (!bm) return;
    bm->setBookmark(Address(nullptr, addr_), type_, text_);
}

// ------------------------------------------------------------------
// DeleteBookmarkEvent
// ------------------------------------------------------------------

void DeleteBookmarkEvent::undo(ProgramDB& program) {
    BookmarkManager* bm = program.getBookmarkManager();
    if (!bm) return;
    bm->setBookmark(Address(nullptr, addr_), type_, text_);
}

void DeleteBookmarkEvent::redo(ProgramDB& program) {
    BookmarkManager* bm = program.getBookmarkManager();
    if (!bm) return;
    bm->removeBookmark(Address(nullptr, addr_), type_);
}

// ------------------------------------------------------------------
// CreateDataTypeEvent
// ------------------------------------------------------------------

void CreateDataTypeEvent::undo(ProgramDB& program) {
    DataTypeManager* dtm = program.getDataTypeManager();
    if (!dtm) return;
    DataType* dt = dtm->getDataType(categoryPath_, name_);
    if (dt) {
        dtm->remove(dt);
    }
}

void CreateDataTypeEvent::redo(ProgramDB& program) {
    DataTypeManager* dtm = program.getDataTypeManager();
    if (!dtm) return;
    DataType* dt = createDataTypeForKind(name_, categoryPath_, size_, typeKind_, dtm);
    dtm->addDataType(dt, nullptr);
}

// ------------------------------------------------------------------
// DeleteDataTypeEvent
// ------------------------------------------------------------------

void DeleteDataTypeEvent::undo(ProgramDB& program) {
    DataTypeManager* dtm = program.getDataTypeManager();
    if (!dtm) return;
    DataType* dt = createDataTypeForKind(name_, categoryPath_, size_, typeKind_, dtm);
    dtm->addDataType(dt, nullptr);
}

void DeleteDataTypeEvent::redo(ProgramDB& program) {
    DataTypeManager* dtm = program.getDataTypeManager();
    if (!dtm) return;
    DataType* dt = dtm->getDataType(categoryPath_, name_);
    if (dt) {
        dtm->remove(dt);
    }
}

// ------------------------------------------------------------------
// SetFunctionSignatureEvent
// ------------------------------------------------------------------

void SetFunctionSignatureEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) func->setSignature(nullptr);
}

void SetFunctionSignatureEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) {
        FunctionSignatureImpl* sig = new FunctionSignatureImpl(name_);
        func->setSignature(sig);
    }
}

// ------------------------------------------------------------------
// SetReturnTypeEvent
// ------------------------------------------------------------------

void SetReturnTypeEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func && func->getReturnType()) {
        DataTypeManager* dtm = program.getDataTypeManager();
        DataType* dt = dtm ? dtm->getDataType(CategoryPath::ROOT(), oldType_) : nullptr;
        func->setReturnType(dt);
    }
}

void SetReturnTypeEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) {
        DataTypeManager* dtm = program.getDataTypeManager();
        DataType* dt = dtm ? dtm->getDataType(CategoryPath::ROOT(), newType_) : nullptr;
        if (dt) func->setReturnType(dt);
    }
}

// ------------------------------------------------------------------
// SetCallingConventionEvent
// ------------------------------------------------------------------

void SetCallingConventionEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func && !oldCc_.empty()) {
        PrototypeModel* cc = fm->getCallingConvention(oldCc_);
        if (cc) func->setCallingConvention(cc);
    }
}

void SetCallingConventionEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func && !newCc_.empty()) {
        PrototypeModel* cc = fm->getCallingConvention(newCc_);
        if (cc) func->setCallingConvention(cc);
    }
}

// ------------------------------------------------------------------
// AddParameterEvent
// ------------------------------------------------------------------

void AddParameterEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) {
        auto& params = func->getParameters();
        for (auto* p : params) {
            if (p && p->getName() == paramName_) {
                func->removeVariable(p);
                break;
            }
        }
    }
}

void AddParameterEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) {
        DataTypeManager* dtm = program.getDataTypeManager();
        DataType* dt = dtm ? dtm->getDataType(CategoryPath::ROOT(), typeName_) : nullptr;
        if (dt) {
            ghidra::VariableStorage vs;
            auto* param = new ParameterImpl(paramName_, dt, vs, static_cast<Program*>(&program));
            func->addParameter(param);
        }
    }
}

// ------------------------------------------------------------------
// RemoveParameterEvent
// ------------------------------------------------------------------

void RemoveParameterEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) {
        DataTypeManager* dtm = program.getDataTypeManager();
        DataType* dt = dtm ? dtm->getDataType(CategoryPath::ROOT(), typeName_) : nullptr;
        if (dt) {
            ghidra::VariableStorage vs;
            auto* param = new ParameterImpl(paramName_, dt, vs, static_cast<Program*>(&program));
            func->addParameter(param);
        }
    }
}

void RemoveParameterEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) {
        auto& params = func->getParameters();
        for (auto* p : params) {
            if (p && p->getName() == paramName_) {
                func->removeVariable(p);
                break;
            }
        }
    }
}

// ------------------------------------------------------------------
// SetNoReturnEvent
// ------------------------------------------------------------------

void SetNoReturnEvent::undo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) func->setHasNoReturn(oldVal_);
}

void SetNoReturnEvent::redo(ProgramDB& program) {
    FunctionManager* fm = program.getFunctionManager();
    if (!fm) return;
    Function* func = fm->getFunctionAt(Address(nullptr, addr_));
    if (func) func->setHasNoReturn(newVal_);
}

} // namespace storage
} // namespace ghidra
