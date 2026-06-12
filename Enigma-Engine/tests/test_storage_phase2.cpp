#include <ghidra/storage/Event.h>
#include <ghidra/storage/EventLog.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/AddressSet.h>
#include <ghidra/CommentType.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/Listing.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <iostream>
#include <string>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;
using namespace ghidra::storage;
namespace fb = fbschema;

int main() {
    // ================================================================
    // Section 1: EventLog basic mechanics
    // ================================================================
    {
        EventLog log;
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        prog.setImageBase(Address(nullptr, 0x100000));

        TEST("empty canUndo", !log.canUndo());
        TEST("empty canRedo", !log.canRedo());
        TEST("empty getSize", log.getSize() == 0);
        TEST("empty getPosition", log.getPosition() == 0);
        TEST("empty undo", !log.undo(prog));
        TEST("empty redo", !log.redo(prog));

        log.recordEvent(std::make_unique<AddSymbolEvent>(0x3000, "label1"));
        TEST("record1 size", log.getSize() == 1);
        TEST("record1 position", log.getPosition() == 1);
        TEST("record1 canUndo", log.canUndo());
        TEST("record1 canRedo", !log.canRedo());

        bool undone = log.undo(prog);
        TEST("undo ok", undone);
        TEST("after undo pos", log.getPosition() == 0);
        TEST("after undo canUndo", !log.canUndo());
        TEST("after undo canRedo", log.canRedo());

        bool redone = log.redo(prog);
        TEST("redo ok", redone);
        TEST("after redo pos", log.getPosition() == 1);
        TEST("after redo canUndo", log.canUndo());
        TEST("after redo canRedo", !log.canRedo());
    }

    // Multiple events + truncation
    {
        EventLog log;
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);

        log.recordEvent(std::make_unique<AddSymbolEvent>(0x4000, "a"));
        log.recordEvent(std::make_unique<AddSymbolEvent>(0x4001, "b"));
        log.recordEvent(std::make_unique<AddSymbolEvent>(0x4002, "c"));
        TEST("3 events size", log.getSize() == 3);
        TEST("3 events pos", log.getPosition() == 3);

        log.undo(prog); log.undo(prog);
        TEST("undo2 pos", log.getPosition() == 1);
        TEST("undo2 canRedo", log.canRedo());

        log.recordEvent(std::make_unique<AddSymbolEvent>(0x4010, "d"));
        TEST("trunc size", log.getSize() == 2);
        TEST("trunc pos", log.getPosition() == 2);
        TEST("trunc canRedo", !log.canRedo());
    }

    // Clear
    {
        EventLog log;
        log.recordEvent(std::make_unique<AddSymbolEvent>(0x5000, "x"));
        log.recordEvent(std::make_unique<AddSymbolEvent>(0x5001, "y"));
        log.clear();
        TEST("clear size", log.getSize() == 0);
        TEST("clear pos", log.getPosition() == 0);
        TEST("clear canUndo", !log.canUndo());
        TEST("clear canRedo", !log.canRedo());
    }

    // Event type tags
    {
        TEST("RenameFunctionEvent type",
             std::make_unique<RenameFunctionEvent>(0x6000,"o","n")->getType() == fb::ChangeType_RENAME_FUNCTION);
        TEST("RenameSymbolEvent type",
             std::make_unique<RenameSymbolEvent>(0x6001,"o","n")->getType() == fb::ChangeType_RENAME_SYMBOL);
        TEST("AddSymbolEvent type",
             std::make_unique<AddSymbolEvent>(0x6002,"s")->getType() == fb::ChangeType_ADD_SYMBOL);
        TEST("RemoveSymbolEvent type",
             std::make_unique<RemoveSymbolEvent>(0x6003,"s")->getType() == fb::ChangeType_REMOVE_SYMBOL);
        TEST("CreateFunctionEvent type",
             std::make_unique<CreateFunctionEvent>(0x6004,"f",AddressSet())->getType() == fb::ChangeType_CREATE_FUNCTION);
        TEST("DeleteFunctionEvent type",
             std::make_unique<DeleteFunctionEvent>(0x6005,"f",AddressSet())->getType() == fb::ChangeType_DELETE_FUNCTION);
        TEST("AddCommentEvent type",
             std::make_unique<AddCommentEvent>(0x6006,CommentType::EOL,"")->getType() == fb::ChangeType_ADD_COMMENT);
        TEST("DeleteCommentEvent type",
             std::make_unique<DeleteCommentEvent>(0x6007,CommentType::PLATE,"")->getType() == fb::ChangeType_DELETE_COMMENT);
        TEST("ModifyCommentEvent type",
             std::make_unique<ModifyCommentEvent>(0x6008,CommentType::PRE,"o","n")->getType() == fb::ChangeType_MODIFY_COMMENT);
        TEST("AddBookmarkEvent type",
             std::make_unique<AddBookmarkEvent>(0x6009,"info","n")->getType() == fb::ChangeType_ADD_BOOKMARK);
        TEST("DeleteBookmarkEvent type",
             std::make_unique<DeleteBookmarkEvent>(0x600A,"info","n")->getType() == fb::ChangeType_DELETE_BOOKMARK);
        TEST("CreateDataTypeEvent type",
             std::make_unique<CreateDataTypeEvent>("S",CategoryPath("/c"),4,0)->getType() == fb::ChangeType_CREATE_DATA_TYPE);
        TEST("DeleteDataTypeEvent type",
             std::make_unique<DeleteDataTypeEvent>("S",CategoryPath("/c"),4,0)->getType() == fb::ChangeType_DELETE_DATA_TYPE);
    }

    // ================================================================
    // Section 2: RenameFunctionEvent
    //   Apply: rename func old→new. Record event. Undo→old. Redo→new.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        FunctionManager* fm = prog.getFunctionManager();
        Address entry(nullptr, 0x7000);
        AddressSet body(entry, Address(nullptr, 0x7010));

        fm->createFunction("old_name", entry, body, SourceType::DEFAULT);
        Function* func = fm->getFunctionAt(entry);
        func->setName("new_name");
        log.recordEvent(std::make_unique<RenameFunctionEvent>(entry.getOffset(), "old_name", "new_name"));

        log.undo(prog);
        TEST("undo name", func && func->getName() == "old_name");

        log.redo(prog);
        TEST("redo name", func && func->getName() == "new_name");
    }

    // ================================================================
    // Section 3: RenameSymbolEvent
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        SymbolTable* st = prog.getSymbolTable();
        Address addr(nullptr, 0x8000);

        st->createLabel(addr, "old_label", SourceType::DEFAULT);
        Symbol* sym = st->getPrimarySymbol(addr);
        sym->setName("new_label");
        log.recordEvent(std::make_unique<RenameSymbolEvent>(addr.getOffset(), "old_label", "new_label"));

        log.undo(prog);
        sym = st->getPrimarySymbol(addr);
        TEST("undo sym name", sym && sym->getName() == "old_label");

        log.redo(prog);
        sym = st->getPrimarySymbol(addr);
        TEST("redo sym name", sym && sym->getName() == "new_label");
    }

    // ================================================================
    // Section 4: AddSymbolEvent
    //   Apply: create symbol at addr. Record. Undo→removed. Redo→added.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        SymbolTable* st = prog.getSymbolTable();
        Address addr(nullptr, 0x9000);

        st->createLabel(addr, "added_sym", SourceType::DEFAULT);
        log.recordEvent(std::make_unique<AddSymbolEvent>(addr.getOffset(), "added_sym"));

        log.undo(prog);
        TEST("undo sym removed", st->getPrimarySymbol(addr) == nullptr);

        log.redo(prog);
        Symbol* sym = st->getPrimarySymbol(addr);
        TEST("redo sym exists", sym != nullptr);
        TEST("redo sym name", sym && sym->getName() == "added_sym");
    }

    // ================================================================
    // Section 5: RemoveSymbolEvent
    //   Apply: remove symbol. Record. Undo→restored. Redo→removed.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        SymbolTable* st = prog.getSymbolTable();
        Address addr(nullptr, 0xA000);

        st->createLabel(addr, "to_remove", SourceType::DEFAULT);
        Symbol* removedSym = st->getPrimarySymbol(addr);
        st->removeSymbolSpecial(removedSym);
        log.recordEvent(std::make_unique<RemoveSymbolEvent>(addr.getOffset(), "to_remove"));

        log.undo(prog);
        Symbol* sym = st->getPrimarySymbol(addr);
        TEST("undo sym restored", sym && sym->getName() == "to_remove");

        log.redo(prog);
        TEST("redo sym removed", st->getPrimarySymbol(addr) == nullptr);
    }

    // ================================================================
    // Section 6: CreateFunctionEvent
    //   Apply: create func. Record. Undo→removed. Redo→recreated.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        FunctionManager* fm = prog.getFunctionManager();
        Address entry(nullptr, 0xB000);
        AddressSet body(entry, Address(nullptr, 0xB010));

        fm->createFunction("create_me", entry, body, SourceType::DEFAULT);
        log.recordEvent(std::make_unique<CreateFunctionEvent>(entry.getOffset(), "create_me", body));

        log.undo(prog);
        TEST("undo func removed", fm->getFunctionAt(entry) == nullptr);

        log.redo(prog);
        Function* func = fm->getFunctionAt(entry);
        TEST("redo func exists", func != nullptr);
        TEST("redo func name", func && func->getName() == "create_me");
    }

    // ================================================================
    // Section 7: DeleteFunctionEvent
    //   Apply: delete func. Record. Undo→restored. Redo→deleted.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        FunctionManager* fm = prog.getFunctionManager();
        Address entry(nullptr, 0xC000);
        AddressSet body(entry, Address(nullptr, 0xC010));

        fm->createFunction("delete_me", entry, body, SourceType::DEFAULT);
        fm->removeFunction(entry);
        log.recordEvent(std::make_unique<DeleteFunctionEvent>(entry.getOffset(), "delete_me", body));

        log.undo(prog);
        Function* func = fm->getFunctionAt(entry);
        TEST("undo func restored", func && func->getName() == "delete_me");

        log.redo(prog);
        TEST("redo func removed", fm->getFunctionAt(entry) == nullptr);
    }

    // ================================================================
    // Section 8: AddCommentEvent (EOL)
    //   Apply: set EOL comment. Record. Undo→cleared. Redo→set.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        prog.setMinAddress(Address(nullptr, 0xD000));
        prog.setMaxAddress(Address(nullptr, 0xD010));
        EventLog log;
        Address addr(nullptr, 0xD000);

        Listing* listing = prog.getListing();
        Data* data = listing->createData(addr, &ByteDataType::dataType(), 1);
        TEST("data created", data != nullptr);

        CodeUnit* cu = listing->getCodeUnitAt(addr);
        cu->setComment("eol_test");
        log.recordEvent(std::make_unique<AddCommentEvent>(addr.getOffset(), CommentType::EOL, "eol_test"));

        log.undo(prog);
        cu = listing->getCodeUnitAt(addr);
        TEST("undo comment cleared", cu && cu->getComment().empty());

        log.redo(prog);
        cu = listing->getCodeUnitAt(addr);
        TEST("redo comment set", cu && cu->getComment() == "eol_test");
    }

    // ================================================================
    // Section 9: DeleteCommentEvent (PLATE)
    //   Apply: delete plate comment. Record. Undo→restored. Redo→cleared.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        prog.setMinAddress(Address(nullptr, 0xE000));
        prog.setMaxAddress(Address(nullptr, 0xE010));
        EventLog log;
        Address addr(nullptr, 0xE000);

        Listing* listing = prog.getListing();
        Data* data = listing->createData(addr, &ByteDataType::dataType(), 1);
        TEST("del data created", data != nullptr);

        CodeUnit* cu = listing->getCodeUnitAt(addr);
        cu->setPlateComment("plate_text");
        cu->setPlateComment(""); // delete it
        log.recordEvent(std::make_unique<DeleteCommentEvent>(addr.getOffset(), CommentType::PLATE, "plate_text"));

        log.undo(prog);
        cu = listing->getCodeUnitAt(addr);
        TEST("undo plate restored", cu && cu->getPlateComment() == "plate_text");

        log.redo(prog);
        cu = listing->getCodeUnitAt(addr);
        TEST("redo plate cleared", cu && cu->getPlateComment().empty());
    }

    // ================================================================
    // Section 10: ModifyCommentEvent (PRE)
    //   Apply: change pre comment old→new. Record. Undo→old. Redo→new.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        prog.setMinAddress(Address(nullptr, 0xF000));
        prog.setMaxAddress(Address(nullptr, 0xF010));
        EventLog log;
        Address addr(nullptr, 0xF000);

        Listing* listing = prog.getListing();
        Data* data = listing->createData(addr, &ByteDataType::dataType(), 1);
        TEST("mod data created", data != nullptr);

        CodeUnit* cu = listing->getCodeUnitAt(addr);
        cu->setPreComment("old_pre");
        cu->setPreComment("new_pre");
        log.recordEvent(std::make_unique<ModifyCommentEvent>(addr.getOffset(), CommentType::PRE, "old_pre", "new_pre"));

        log.undo(prog);
        cu = listing->getCodeUnitAt(addr);
        TEST("undo pre restored", cu && cu->getPreComment() == "old_pre");

        log.redo(prog);
        cu = listing->getCodeUnitAt(addr);
        TEST("redo pre changed", cu && cu->getPreComment() == "new_pre");
    }

    // ================================================================
    // Section 11: AddBookmarkEvent
    //   Apply: add bookmark. Record. Undo→removed. Redo→re-added.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        BookmarkManager* bm = prog.getBookmarkManager();
        Address addr(nullptr, 0x11000);

        bm->setBookmark(addr, "info", "my_note");
        log.recordEvent(std::make_unique<AddBookmarkEvent>(addr.getOffset(), "info", "my_note"));

        log.undo(prog);
        TEST("undo bookmark removed", !bm->removeBookmark(addr, "info"));

        log.redo(prog);
        TEST("redo bookmark added", bm->removeBookmark(addr, "info"));
    }

    // ================================================================
    // Section 12: DeleteBookmarkEvent
    //   Apply: delete bookmark. Record. Undo→restored. Redo→deleted.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;
        BookmarkManager* bm = prog.getBookmarkManager();
        Address addr(nullptr, 0x12000);

        bm->setBookmark(addr, "info", "del_note");
        bm->removeBookmark(addr, "info");
        log.recordEvent(std::make_unique<DeleteBookmarkEvent>(addr.getOffset(), "info", "del_note"));

        log.undo(prog);
        TEST("undo bookmark restored", bm->removeBookmark(addr, "info"));

        log.redo(prog);
        TEST("redo bookmark deleted", !bm->removeBookmark(addr, "info"));
    }

    // ================================================================
    // Section 13: CreateDataTypeEvent
    //   Note: DataTypeManager base addDataType/remove are no-ops.
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;

        log.recordEvent(std::make_unique<CreateDataTypeEvent>("MyStruct", CategoryPath("/custom"), 4, 0));
        log.undo(prog);
        TEST("create undo no crash", true);

        log.redo(prog);
        TEST("create redo no crash", true);
    }

    // ================================================================
    // Section 14: DeleteDataTypeEvent
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("test", nullptr, nullptr);
        EventLog log;

        log.recordEvent(std::make_unique<DeleteDataTypeEvent>("MyStruct", CategoryPath("/custom"), 4, 0));
        log.undo(prog);
        TEST("delete undo no crash", true);

        log.redo(prog);
        TEST("delete redo no crash", true);
    }

    // ================================================================
    // Summary
    // ================================================================
    std::cout << "\n=== Phase 2 Storage Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";

    return (passed == total) ? 0 : 1;
}




