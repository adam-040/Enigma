/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DatabaseAdapter.cpp
/// \brief SQLite database adapter implementation
#include "ghidra/DatabaseAdapter.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/Memory.h"
#include "ghidra/Msg.h"
#include "ghidra/SourceType.h"
#include "ghidra/ReferenceManager.h"
#include "ghidra/BookmarkManager.h"
#include "ghidra/RefType.h"
#include "ghidra/DataTypeManagerImpl.h"
#include "ghidra/StructureDataType.h"
#include "ghidra/UnionDataType.h"
#include "ghidra/EnumDataType.h"
#include "ghidra/TypedefDataType.h"
#include "ghidra/ArrayDataType.h"
#include "ghidra/PointerDataType.h"
#include "ghidra/Composite.h"
#include "ghidra/DataTypeComponent.h"
#include "ghidra/Comment.h"
#include "ghidra/Listing.h"
#include "ghidra/CodeUnit.h"
#include "ghidra/Instruction.h"
#include "ghidra/Data.h"
#include "ghidra/EquateTable.h"
#include "ghidra/RelocationTableImpl.h"
#include "ghidra/ExternalManagerImpl.h"
#include "ghidra/SourceFileManagerImpl.h"
#include "ghidra/PropertyMapManagerImpl.h"
#include "ghidra/TreeManager.h"
#include "ghidra/ModuleManager.h"
#include "ghidra/ModuleDB.h"
#include "ghidra/FragmentDB.h"
#include "ghidra/LocalVariableImpl.h"
#include "ghidra/FunctionTagManagerImpl.h"
#include "ghidra/FunctionTagImpl.h"
#include "ghidra/ParameterImpl.h"
#include "ghidra/AutoParameterImpl.h"
#include "ghidra/ReturnParameterImpl.h"
#include "ghidra/SignatureSource.h"
#include "ghidra/FunctionSignatureImpl.h"
#include "ghidra/VariableStorage.h"

#include <sqlite3.h>
#include <sstream>
#include <cstdlib>

namespace ghidra {

namespace {

std::string toHexLiteral(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return "NULL";
    std::string hex = "X'";
    static const char* const lut = "0123456789ABCDEF";
    for (uint8_t b : bytes) {
        hex.push_back(lut[b >> 4]);
        hex.push_back(lut[b & 15]);
    }
    hex.push_back('\'');
    return hex;
}

std::vector<uint8_t> parseHexBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.empty() || hex == "NULL") return bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtoul(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

} // namespace

std::string DatabaseAdapter::escapeString(const std::string& input) {
    std::string result;
    result.reserve(input.size() * 2);
    for (char c : input) {
        if (c == '\'') result += "\'\'";
        else if (c == '\\') result += "\\\\";
        else result += c;
    }
    return result;
}

int64_t DatabaseAdapter::addressToLong(const Address& addr) {
    return addr.getOffset();
}

Address DatabaseAdapter::longToAddress(int64_t value) {
    return Address();
}

class SQLiteDatabaseAdapter : public DatabaseAdapter {
public:
    SQLiteDatabaseAdapter() : db_(nullptr), inTransaction_(false) {}

    ~SQLiteDatabaseAdapter() override {
        close();
    }

    bool open(const std::string& filePath, bool createIfMissing) override {
        int flags = SQLITE_OPEN_READWRITE;
        if (createIfMissing) flags |= SQLITE_OPEN_CREATE;

        int rc = sqlite3_open_v2(filePath.c_str(), &db_, flags, nullptr);
        if (rc != SQLITE_OK) {
            lastError_ = sqlite3_errmsg(db_);
            sqlite3_close(db_);
            db_ = nullptr;
            return false;
        }

        sqlite3_exec(db_, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA synchronous=NORMAL", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA foreign_keys=ON", nullptr, nullptr, nullptr);

        return true;
    }

    void close() override {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        inTransaction_ = false;
    }

    bool isOpen() const override { return db_ != nullptr; }

    bool execute(const std::string& sql) override {
        if (!db_) return false;
        char* errMsg = nullptr;
        int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            lastError_ = errMsg ? errMsg : "Unknown error";
            if (errMsg) sqlite3_free(errMsg);
            return false;
        }
        return true;
    }

    DBResult query(const std::string& sql) override {
        DBResult result;
        if (!db_) return result;

        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            lastError_ = sqlite3_errmsg(db_);
            return result;
        }

        int colCount = sqlite3_column_count(stmt);
        for (int i = 0; i < colCount; ++i) {
            result.columns.push_back(sqlite3_column_name(stmt, i));
        }

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            std::vector<std::string> row;
            for (int i = 0; i < colCount; ++i) {
                const unsigned char* text = sqlite3_column_text(stmt, i);
                if (text) {
                    row.push_back(reinterpret_cast<const char*>(text));
                } else {
                    row.push_back("");
                }
            }
            result.rows.push_back(row);
        }

        sqlite3_finalize(stmt);
        return result;
    }

    int64_t lastInsertRowId() const override {
        return db_ ? sqlite3_last_insert_rowid(db_) : 0;
    }

    int changes() const override {
        return db_ ? sqlite3_changes(db_) : 0;
    }

    bool beginTransaction() override {
        if (inTransaction_) return false;
        bool ok = execute("BEGIN TRANSACTION");
        if (ok) inTransaction_ = true;
        return ok;
    }

    bool commitTransaction() override {
        if (!inTransaction_) return false;
        bool ok = execute("COMMIT");
        if (ok) inTransaction_ = false;
        return ok;
    }

    bool rollbackTransaction() override {
        if (!inTransaction_) return false;
        bool ok = execute("ROLLBACK");
        if (ok) inTransaction_ = false;
        return ok;
    }

    bool createSchema() override {
        const char* schemaSQL[] = {
            "CREATE TABLE IF NOT EXISTS program_info ("
            "  id INTEGER PRIMARY KEY,"
            "  name TEXT NOT NULL,"
            "  language_id TEXT,"
            "  compiler_spec_id TEXT,"
            "  image_base TEXT,"
            "  db_version INTEGER DEFAULT 33,"
            "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",

            "CREATE TABLE IF NOT EXISTS memory_blocks ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  name TEXT NOT NULL,"
            "  start_addr TEXT NOT NULL,"
            "  size INTEGER NOT NULL,"
            "  is_initialized INTEGER DEFAULT 0,"
            "  is_read INTEGER DEFAULT 1,"
            "  is_write INTEGER DEFAULT 1,"
            "  is_execute INTEGER DEFAULT 0,"
            "  is_volatile INTEGER DEFAULT 0,"
            "  data BLOB)",

            "CREATE TABLE IF NOT EXISTS symbols ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  name TEXT NOT NULL,"
            "  address TEXT NOT NULL,"
            "  namespace_id INTEGER DEFAULT 0,"
            "  symbol_type INTEGER DEFAULT 0,"
            "  source_type INTEGER DEFAULT 0,"
            "  is_primary INTEGER DEFAULT 0,"
            "  is_external INTEGER DEFAULT 0,"
            "  is_dynamic INTEGER DEFAULT 0)",

            "CREATE TABLE IF NOT EXISTS namespaces ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  name TEXT NOT NULL,"
            "  parent_id INTEGER DEFAULT 0,"
            "  namespace_type INTEGER DEFAULT 0)",

            "CREATE TABLE IF NOT EXISTS functions ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  name TEXT NOT NULL,"
            "  entry_point TEXT NOT NULL,"
            "  calling_convention TEXT,"
            "  return_type TEXT,"
            "  signature TEXT,"
            "  signature_source INTEGER DEFAULT 0,"
            "  is_thunk INTEGER DEFAULT 0,"
            "  is_external INTEGER DEFAULT 0,"
            "  has_no_return INTEGER DEFAULT 0,"
            "  is_inline INTEGER DEFAULT 0,"
            "  is_constructor INTEGER DEFAULT 0,"
            "  is_destructor INTEGER DEFAULT 0,"
            "  call_fixup TEXT,"
            "  stack_frame_size INTEGER DEFAULT 0)",

            "CREATE TABLE IF NOT EXISTS \"references\" ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  from_addr TEXT NOT NULL,"
            "  to_addr TEXT NOT NULL,"
            "  ref_type INTEGER NOT NULL,"
            "  source_type INTEGER DEFAULT 0,"
            "  op_index INTEGER DEFAULT -1)",

            "CREATE TABLE IF NOT EXISTS bookmarks ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  address TEXT NOT NULL,"
            "  type TEXT NOT NULL,"
            "  category TEXT,"
            "  description TEXT)",

            "CREATE TABLE IF NOT EXISTS comments ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  address TEXT NOT NULL,"
            "  comment_type INTEGER NOT NULL,"
            "  text TEXT)",

            "CREATE TABLE IF NOT EXISTS properties ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  name TEXT NOT NULL,"
            "  value TEXT)",

            "CREATE TABLE IF NOT EXISTS datatypes ("
            "  id INTEGER PRIMARY KEY,"
            "  category TEXT NOT NULL,"
            "  name TEXT NOT NULL,"
            "  type_kind TEXT NOT NULL,"
            "  length INTEGER NOT NULL,"
            "  referred_type_id INTEGER,"
            "  array_element_count INTEGER)",

            "CREATE TABLE IF NOT EXISTS datatype_components ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  parent_type_id INTEGER NOT NULL,"
            "  member_type_id INTEGER NOT NULL,"
            "  member_name TEXT NOT NULL,"
            "  offset INTEGER NOT NULL,"
            "  length INTEGER NOT NULL,"
            "  FOREIGN KEY(parent_type_id) REFERENCES datatypes(id))",

            "CREATE TABLE IF NOT EXISTS enum_values ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  enum_type_id INTEGER NOT NULL,"
            "  name TEXT NOT NULL,"
            "  value INTEGER NOT NULL,"
            "  FOREIGN KEY(enum_type_id) REFERENCES datatypes(id))",

            "CREATE TABLE IF NOT EXISTS equates ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  name TEXT NOT NULL,"
            "  value INTEGER NOT NULL)",

            "CREATE TABLE IF NOT EXISTS relocations ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  address TEXT NOT NULL,"
            "  type INTEGER NOT NULL,"
            "  symbol_name TEXT)",

            "CREATE INDEX IF NOT EXISTS idx_symbols_address ON symbols(address)",
            "CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name)",
            "CREATE INDEX IF NOT EXISTS idx_functions_entry ON functions(entry_point)",
            "CREATE INDEX IF NOT EXISTS idx_references_from ON \"references\"(from_addr)",
            "CREATE INDEX IF NOT EXISTS idx_references_to ON \"references\"(to_addr)",
            "CREATE INDEX IF NOT EXISTS idx_bookmarks_address ON bookmarks(address)",
            "CREATE INDEX IF NOT EXISTS idx_comments_address ON comments(address)",
            "CREATE INDEX IF NOT EXISTS idx_datatypes_name ON datatypes(name)",
            "CREATE INDEX IF NOT EXISTS idx_datatype_components_parent ON datatype_components(parent_type_id)",
            "CREATE INDEX IF NOT EXISTS idx_enum_values_type ON enum_values(enum_type_id)",
            "CREATE INDEX IF NOT EXISTS idx_equates_name ON equates(name)",
            "CREATE INDEX IF NOT EXISTS idx_relocations_address ON relocations(address)",

            "CREATE TABLE IF NOT EXISTS external_locations ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  library_name TEXT NOT NULL,"
            "  label TEXT NOT NULL,"
            "  address TEXT)",

            "CREATE TABLE IF NOT EXISTS source_files ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  path TEXT NOT NULL,"
            "  compiler_spec TEXT,"
            "  id_type INTEGER,"
            "  id_bytes BLOB)",

            "CREATE TABLE IF NOT EXISTS int_range_maps ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  map_name TEXT NOT NULL,"
            "  start_address TEXT NOT NULL,"
            "  end_address TEXT NOT NULL,"
            "  value INTEGER NOT NULL)",

            "CREATE TABLE IF NOT EXISTS source_map_entries ("
            "  file_id INTEGER NOT NULL,"
            "  line_number INTEGER NOT NULL,"
            "  start_address TEXT NOT NULL,"
            "  end_address TEXT NOT NULL,"
            "  length INTEGER NOT NULL)",

            "CREATE TABLE IF NOT EXISTS program_register_values ("
            "  register_name TEXT NOT NULL,"
            "  start_address TEXT NOT NULL,"
            "  end_address TEXT NOT NULL,"
            "  value_bytes BLOB,"
            "  uint64_value INTEGER,"
            "  is_uint64 INTEGER NOT NULL)",

            "CREATE TABLE IF NOT EXISTS program_register_default_values ("
            "  register_name TEXT NOT NULL,"
            "  start_address TEXT NOT NULL,"
            "  end_address TEXT NOT NULL,"
            "  value_bytes BLOB)",

            "CREATE INDEX IF NOT EXISTS idx_external_locations_lib ON external_locations(library_name)",
            "CREATE INDEX IF NOT EXISTS idx_source_files_path ON source_files(path)",
            "CREATE INDEX IF NOT EXISTS idx_int_range_maps_name ON int_range_maps(map_name)",
            "CREATE INDEX IF NOT EXISTS idx_source_map_entries_file ON source_map_entries(file_id)",
            "CREATE INDEX IF NOT EXISTS idx_source_map_entries_addr ON source_map_entries(start_address)",
            "CREATE INDEX IF NOT EXISTS idx_register_values_name ON program_register_values(register_name)",
            "CREATE INDEX IF NOT EXISTS idx_register_default_values_name ON program_register_default_values(register_name)",

            "CREATE TABLE IF NOT EXISTS trees ("
            "  id INTEGER PRIMARY KEY,"
            "  name TEXT NOT NULL,"
            "  modification_number INTEGER NOT NULL)",

            "CREATE TABLE IF NOT EXISTS tree_modules ("
            "  id INTEGER,"
            "  tree_id INTEGER NOT NULL,"
            "  name TEXT NOT NULL,"
            "  comment TEXT,"
            "  PRIMARY KEY (tree_id, id))",

            "CREATE TABLE IF NOT EXISTS tree_fragments ("
            "  id INTEGER,"
            "  tree_id INTEGER NOT NULL,"
            "  name TEXT NOT NULL,"
            "  comment TEXT,"
            "  PRIMARY KEY (tree_id, id))",

            "CREATE TABLE IF NOT EXISTS tree_relationships ("
            "  tree_id INTEGER NOT NULL,"
            "  parent_id INTEGER NOT NULL,"
            "  child_id INTEGER NOT NULL,"
            "  order_idx INTEGER NOT NULL,"
            "  PRIMARY KEY (tree_id, parent_id, child_id))",

            "CREATE TABLE IF NOT EXISTS tree_fragment_ranges ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  tree_id INTEGER NOT NULL,"
            "  fragment_id INTEGER NOT NULL,"
            "  start_address TEXT NOT NULL,"
            "  end_address TEXT NOT NULL)",

            "CREATE INDEX IF NOT EXISTS idx_tree_modules_tree ON tree_modules(tree_id)",
            "CREATE INDEX IF NOT EXISTS idx_tree_fragments_tree ON tree_fragments(tree_id)",
            "CREATE INDEX IF NOT EXISTS idx_tree_relationships_tree ON tree_relationships(tree_id)",
            "CREATE INDEX IF NOT EXISTS idx_tree_fragment_ranges_frag ON tree_fragment_ranges(tree_id, fragment_id)",

            "CREATE TABLE IF NOT EXISTS function_variables ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  function_entry TEXT NOT NULL,"
            "  var_kind TEXT NOT NULL,"
            "  name TEXT NOT NULL,"
            "  datatype_id INTEGER NOT NULL,"
            "  storage TEXT NOT NULL,"
            "  comment TEXT,"
            "  source_type INTEGER DEFAULT 0,"
            "  ordinal INTEGER DEFAULT -1,"
            "  first_use_offset INTEGER DEFAULT 0,"
            "  auto_param_type INTEGER DEFAULT -1)",

            "CREATE INDEX IF NOT EXISTS idx_function_variables_entry ON function_variables(function_entry)",

            "CREATE TABLE IF NOT EXISTS function_tags ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  name TEXT UNIQUE NOT NULL,"
            "  comment TEXT)",

            "CREATE TABLE IF NOT EXISTS function_tag_mappings ("
            "  function_entry TEXT NOT NULL,"
            "  tag_id INTEGER NOT NULL,"
            "  PRIMARY KEY (function_entry, tag_id))",

            "CREATE INDEX IF NOT EXISTS idx_function_tag_mappings_tag ON function_tag_mappings(tag_id)",

            nullptr
        };

        for (int i = 0; schemaSQL[i] != nullptr; ++i) {
            if (!execute(schemaSQL[i])) {
                return false;
            }
        }

        return true;
    }

    bool populateProgram(ProgramDB* program) override {
        if (!program || !db_) return false;

        beginTransaction();

        execute("DELETE FROM program_info");
        execute("DELETE FROM memory_blocks");
        execute("DELETE FROM symbols");
        execute("DELETE FROM functions");
        execute("DELETE FROM \"references\"");
        execute("DELETE FROM bookmarks");
        execute("DELETE FROM namespaces");
        execute("DELETE FROM comments");
        execute("DELETE FROM equates");
        execute("DELETE FROM relocations");
        execute("DELETE FROM function_variables");
        execute("DELETE FROM function_tags");
        execute("DELETE FROM function_tag_mappings");

        std::string name = escapeString(program->getName());
        std::string langId = escapeString(program->getLanguageID().getIdAsString());
        std::string compilerId = escapeString(program->getCompilerSpecID().toString());

        std::string sql = "INSERT INTO program_info (name, language_id, compiler_spec_id, db_version) "
                          "VALUES ('" + name + "', '" + langId + "', '" + compilerId + "', 33)";
        if (!execute(sql)) {
            rollbackTransaction();
            return false;
        }

        Memory* mem = program->getMemory();
        if (mem) {
            for (auto* block : mem->getBlocks()) {
                std::string blockName = escapeString(block->getName());
                std::string startAddr = escapeString(block->getStart().toString());
                int64_t size = block->getSize();
                int isRead = block->isRead() ? 1 : 0;
                int isWrite = block->isWrite() ? 1 : 0;
                int isExecute = block->isExecute() ? 1 : 0;
                int isVolatile = block->isVolatile() ? 1 : 0;

                int isInitialized = block->isInitialized() ? 1 : 0;
                sql = "INSERT INTO memory_blocks (name, start_addr, size, is_initialized, "
                      "is_read, is_write, is_execute, is_volatile) VALUES ('" +
                      blockName + "', '" + startAddr + "', " + std::to_string(size) + ", " +
                      std::to_string(isInitialized) + ", " +
                      std::to_string(isRead) + ", " + std::to_string(isWrite) + ", " +
                      std::to_string(isExecute) + ", " + std::to_string(isVolatile) + ")";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }
        }

        SymbolTable* symTable = program->getSymbolTable();
        if (symTable) {
            for (const auto& pair : symTable->getNamespaces()) {
                long nsId = pair.first;
                Namespace* ns = pair.second.get();
                if (!ns) continue;
                std::string nsName = escapeString(ns->getName());
                long parentId = ns->getParent() ? ns->getParent()->getID() : 0;
                sql = "INSERT OR REPLACE INTO namespaces (id, name, parent_id, namespace_type) VALUES (" +
                      std::to_string(nsId) + ", '" + nsName + "', " + std::to_string(parentId) + ", 0)";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }

            auto allSyms = symTable->getAllProgramSymbols(false);
            while (allSyms.hasNext()) {
                Symbol* sym = allSyms.next();
                std::string symName = escapeString(sym->getName());
                std::string addr = escapeString(sym->getAddress().toString());
                int symType = static_cast<int>(sym->getSymbolType());
                int sourceType = static_cast<int>(sym->getSource());
                int isPrimary = sym->isPrimary() ? 1 : 0;
                int isExternal = sym->isExternal() ? 1 : 0;
                long nsId = sym->getParentNamespace() ? sym->getParentNamespace()->getID() : 0;

                sql = "INSERT INTO symbols (name, address, namespace_id, symbol_type, source_type, "
                      "is_primary, is_external) VALUES ('" +
                      symName + "', '" + addr + "', " + std::to_string(nsId) + ", " +
                      std::to_string(symType) + ", " + std::to_string(sourceType) + ", " +
                      std::to_string(isPrimary) + ", " + std::to_string(isExternal) + ")";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }
        }

        FunctionManager* funcMgr = program->getFunctionManager();
        if (funcMgr) {
            auto funcIter = funcMgr->getFunctions(true);
            while (funcIter.hasNext()) {
                Function* func = funcIter.next();
                std::string funcName = escapeString(func->getName());
                std::string entryPoint = escapeString(func->getEntryPoint().toString());
                int isThunk = func->isThunk() ? 1 : 0;
                int isExternal = func->isExternal() ? 1 : 0;
                int hasNoReturn = func->hasNoReturn() ? 1 : 0;
                int isInline = func->isInline() ? 1 : 0;
                int stackFrameSize = func->getStackFrameSize();

                sql = "INSERT INTO functions (name, entry_point, is_thunk, is_external, "
                      "has_no_return, is_inline, stack_frame_size, calling_convention, "
                      "return_type, signature, signature_source) VALUES ('" +
                      funcName + "', '" + entryPoint + "', " + std::to_string(isThunk) + ", " +
                      std::to_string(isExternal) + ", " + std::to_string(hasNoReturn) + ", " +
                      std::to_string(isInline) + ", " + std::to_string(stackFrameSize) + ", '" +
                      escapeString(func->getCallingConvention() ? func->getCallingConvention()->getName() : "") + "', '" +
                      escapeString(func->getReturnType() ? func->getReturnType()->getName() : "") + "', '" +
                      escapeString(func->getSignature() ? func->getSignature()->getPrototypeString() : "") + "', " +
                      std::to_string(static_cast<int>(func->getSignatureSource())) + ")";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }

                // Save function variables and parameters (Wave 67)
                auto* dtMgr = dynamic_cast<DataTypeManagerImpl*>(program->getDataTypeManager());
                for (auto* var : func->getParameters()) {
                    if (!var) continue;
                    auto* param = dynamic_cast<Parameter*>(var);
                    if (!param) continue;
                    std::string varKind = "parameter";
                    int autoParamTypeVal = -1;
                    if (param->isAutoParameter()) {
                        varKind = "auto_parameter";
                        autoParamTypeVal = static_cast<int>(param->getAutoParameterType());
                    } else if (param->getOrdinal() == Parameter::RETURN_ORDINAL) {
                        varKind = "return_parameter";
                    }
                    std::string varName = escapeString(param->getName());
                    long dtId = -1;
                    if (dtMgr && param->getDataType()) {
                        dtId = dtMgr->getDataTypeId(param->getDataType());
                    }
                    std::string storageStr = escapeString(param->getVariableStorage().getSerializationString());
                    std::string comment = escapeString(param->getComment());
                    int sourceTypeVal = static_cast<int>(param->getSource());
                    int ordinal = param->getOrdinal();

                    sql = "INSERT INTO function_variables (function_entry, var_kind, name, datatype_id, storage, "
                          "comment, source_type, ordinal, first_use_offset, auto_param_type) VALUES ('" +
                          entryPoint + "', '" + varKind + "', '" + varName + "', " + std::to_string(dtId) + ", '" +
                          storageStr + "', '" + comment + "', " + std::to_string(sourceTypeVal) + ", " +
                          std::to_string(ordinal) + ", 0, " + std::to_string(autoParamTypeVal) + ")";
                    if (!execute(sql)) {
                        rollbackTransaction();
                        return false;
                    }
                }

                for (auto* var : func->getLocalVariables()) {
                    if (!var) continue;
                    std::string varKind = "local";
                    std::string varName = escapeString(var->getName());
                    long dtId = -1;
                    if (dtMgr && var->getDataType()) {
                        dtId = dtMgr->getDataTypeId(var->getDataType());
                    }
                    std::string storageStr = escapeString(var->getVariableStorage().getSerializationString());
                    std::string comment = escapeString(var->getComment());
                    int sourceTypeVal = static_cast<int>(var->getSource());
                    int firstUseOffset = var->getFirstUseOffset();

                    sql = "INSERT INTO function_variables (function_entry, var_kind, name, datatype_id, storage, "
                          "comment, source_type, ordinal, first_use_offset, auto_param_type) VALUES ('" +
                          entryPoint + "', '" + varKind + "', '" + varName + "', " + std::to_string(dtId) + ", '" +
                          storageStr + "', '" + comment + "', " + std::to_string(sourceTypeVal) + ", -1, " +
                          std::to_string(firstUseOffset) + ", -1)";
                    if (!execute(sql)) {
                        rollbackTransaction();
                        return false;
                    }
                }
            }
        }

        auto* tagMgr = program->getFunctionTagManager();
        if (tagMgr) {
            auto tags = tagMgr->getAllFunctionTags();
            for (auto* tag : tags) {
                if (!tag) continue;
                sql = "INSERT INTO function_tags (id, name, comment) VALUES (" +
                      std::to_string(tag->getId()) + ", '" + escapeString(tag->getName()) + "', '" +
                      escapeString(tag->getComment()) + "')";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }
        }

        if (funcMgr) {
            auto iter = funcMgr->getFunctions();
            while (iter.hasNext()) {
                auto* func = iter.next();
                if (!func) continue;
                std::string entryPoint = escapeString(func->getEntryPoint().toString());
                for (auto* tag : func->getTags()) {
                    if (!tag) continue;
                    sql = "INSERT INTO function_tag_mappings (function_entry, tag_id) VALUES ('" +
                          entryPoint + "', " + std::to_string(tag->getId()) + ")";
                    if (!execute(sql)) {
                        rollbackTransaction();
                        return false;
                    }
                }
            }
        }

        auto* refMgr = program->getReferenceManager();
        if (refMgr) {
            auto allRefs = refMgr->getAllReferences();
            for (auto* ref : allRefs) {
                std::string fromAddr = escapeString(ref->getFromAddress().toString());
                std::string toAddr = escapeString(ref->getToAddress().toString());
                int refTypeVal = ref->getReferenceType() ? static_cast<int>(ref->getReferenceType()->getValue()) : 0;
                int opIndex = ref->getOperandIndex();
                sql = "INSERT INTO \"references\" (from_addr, to_addr, ref_type, op_index) VALUES ('" +
                      fromAddr + "', '" + toAddr + "', " + std::to_string(refTypeVal) + ", " +
                      std::to_string(opIndex) + ")";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }
        }

        auto* bmMgr = program->getBookmarkManager();
        if (bmMgr) {
            auto allBm = bmMgr->getAllBookmarks();
            for (auto* bm : allBm) {
                std::string bmAddr = escapeString(bm->getAddress().toString());
                std::string bmType = escapeString(bm->getType());
                std::string bmDesc = escapeString(bm->getComment());
                sql = "INSERT INTO bookmarks (address, type, description) VALUES ('" +
                      bmAddr + "', '" + bmType + "', '" + bmDesc + "')";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }
        }

        // Wave 59: DataTypeManager persistence logic (Save)
        execute("DELETE FROM enum_values");
        execute("DELETE FROM datatype_components");
        execute("DELETE FROM datatypes");

        auto* dtMgr = dynamic_cast<DataTypeManagerImpl*>(program->getDataTypeManager());
        if (dtMgr) {
            std::vector<DataType*> allTypes = dtMgr->getDataTypes();
            // Insert datatypes first
            for (auto* dt : allTypes) {
                if (!dt) continue;
                long id = dtMgr->getDataTypeId(dt);
                if (id == -1) continue;

                std::string category = escapeString(dt->getCategoryPath().getPath());
                std::string name = escapeString(dt->getName());
                std::string type_kind = "builtin";
                std::string referred_type_id_str = "NULL";
                std::string array_element_count_str = "NULL";

                if (dynamic_cast<StructureDataType*>(dt)) {
                    type_kind = "structure";
                } else if (dynamic_cast<UnionDataType*>(dt)) {
                    type_kind = "union";
                } else if (dynamic_cast<EnumDataType*>(dt)) {
                    type_kind = "enum";
                } else if (auto* typedefDt = dynamic_cast<TypedefDataType*>(dt)) {
                    type_kind = "typedef";
                    long refId = dtMgr->getDataTypeId(typedefDt->getDataType());
                    if (refId != -1) referred_type_id_str = std::to_string(refId);
                } else if (auto* pointerDt = dynamic_cast<PointerDataType*>(dt)) {
                    type_kind = "pointer";
                    long refId = dtMgr->getDataTypeId(pointerDt->getDataType());
                    if (refId != -1) referred_type_id_str = std::to_string(refId);
                } else if (auto* arrayDt = dynamic_cast<ArrayDataType*>(dt)) {
                    type_kind = "array";
                    long refId = dtMgr->getDataTypeId(arrayDt->getDataType());
                    if (refId != -1) referred_type_id_str = std::to_string(refId);
                    array_element_count_str = std::to_string(arrayDt->getNumElements());
                }

                sql = "INSERT OR REPLACE INTO datatypes (id, category, name, type_kind, length, referred_type_id, array_element_count) VALUES (" +
                      std::to_string(id) + ", '" + category + "', '" + name + "', '" + type_kind + "', " +
                      std::to_string(dt->getLength()) + ", " + referred_type_id_str + ", " + array_element_count_str + ")";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }

            // Insert components and enum values
            for (auto* dt : allTypes) {
                if (!dt) continue;
                long id = dtMgr->getDataTypeId(dt);
                if (id == -1) continue;

                if (auto* structDt = dynamic_cast<StructureDataType*>(dt)) {
                    for (auto* comp : structDt->getComponents()) {
                        if (!comp) continue;
                        DataType* compDt = comp->getDataType();
                        long compDtId = dtMgr->getDataTypeId(compDt);
                        if (compDtId == -1 && compDt) {
                            compDt = dtMgr->addDataType(compDt);
                            compDtId = dtMgr->getDataTypeId(compDt);
                        }
                        if (compDtId == -1) continue;

                        std::string compName = escapeString(comp->getFieldName());
                        sql = "INSERT INTO datatype_components (parent_type_id, member_type_id, member_name, offset, length) VALUES (" +
                              std::to_string(id) + ", " + std::to_string(compDtId) + ", '" + compName + "', " +
                              std::to_string(comp->getOffset()) + ", " + std::to_string(comp->getLength()) + ")";
                        if (!execute(sql)) {
                            rollbackTransaction();
                            return false;
                        }
                    }
                } else if (auto* unionDt = dynamic_cast<UnionDataType*>(dt)) {
                    for (auto* comp : unionDt->getComponents()) {
                        if (!comp) continue;
                        DataType* compDt = comp->getDataType();
                        long compDtId = dtMgr->getDataTypeId(compDt);
                        if (compDtId == -1 && compDt) {
                            compDt = dtMgr->addDataType(compDt);
                            compDtId = dtMgr->getDataTypeId(compDt);
                        }
                        if (compDtId == -1) continue;

                        std::string compName = escapeString(comp->getFieldName());
                        sql = "INSERT INTO datatype_components (parent_type_id, member_type_id, member_name, offset, length) VALUES (" +
                              std::to_string(id) + ", " + std::to_string(compDtId) + ", '" + compName + "', " +
                              std::to_string(comp->getOffset()) + ", " + std::to_string(comp->getLength()) + ")";
                        if (!execute(sql)) {
                            rollbackTransaction();
                            return false;
                        }
                    }
                } else if (auto* enumDt = dynamic_cast<EnumDataType*>(dt)) {
                    for (const auto& nameVal : enumDt->getNames()) {
                        long long val = enumDt->getValue(nameVal);
                        sql = "INSERT INTO enum_values (enum_type_id, name, value) VALUES (" +
                              std::to_string(id) + ", '" + escapeString(nameVal) + "', " + std::to_string(val) + ")";
                        if (!execute(sql)) {
                            rollbackTransaction();
                            return false;
                        }
                    }
                }
            }
        }

        Listing* listing = program->getListing();
        if (listing) {
            Address minAddr = program->getMinAddress();
            Address maxAddr = program->getMaxAddress();
            if (!minAddr.isValid() || !maxAddr.isValid()) {
                Memory* mem = program->getMemory();
                if (mem) {
                    auto blocks = mem->getBlocks();
                    if (!blocks.empty()) {
                        bool first = true;
                        for (auto* block : blocks) {
                            if (!block) continue;
                            if (first) {
                                minAddr = block->getStart();
                                maxAddr = block->getEnd();
                                first = false;
                            } else {
                                if (block->getStart() < minAddr) {
                                    minAddr = block->getStart();
                                }
                                if (maxAddr < block->getEnd()) {
                                    maxAddr = block->getEnd();
                                }
                            }
                        }
                    }
                }
            }
            if (minAddr.isValid() && maxAddr.isValid()) {
                AddressSet wholeRange(minAddr, maxAddr);
                for (auto* inst : listing->getInstructions(wholeRange)) {
                    if (!inst) continue;
                    std::string addrStr = escapeString(inst->getAddress().toString());
                    if (!inst->getComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::EOL_COMMENT)) + ", '" +
                              escapeString(inst->getComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                    if (!inst->getPreComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::PRE_COMMENT)) + ", '" +
                              escapeString(inst->getPreComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                    if (!inst->getPostComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::POST_COMMENT)) + ", '" +
                              escapeString(inst->getPostComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                    if (!inst->getPlateComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::PLATE_COMMENT)) + ", '" +
                              escapeString(inst->getPlateComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                }
                for (auto* data : listing->getData(wholeRange)) {
                    if (!data) continue;
                    std::string addrStr = escapeString(data->getAddress().toString());
                    if (!data->getComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::EOL_COMMENT)) + ", '" +
                              escapeString(data->getComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                    if (!data->getPreComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::PRE_COMMENT)) + ", '" +
                              escapeString(data->getPreComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                    if (!data->getPostComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::POST_COMMENT)) + ", '" +
                              escapeString(data->getPostComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                    if (!data->getPlateComment().empty()) {
                        sql = "INSERT INTO comments (address, comment_type, text) VALUES ('" +
                              addrStr + "', " + std::to_string(static_cast<int>(Comment::Type::PLATE_COMMENT)) + ", '" +
                              escapeString(data->getPlateComment()) + "')";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                }
            }
        }

        auto* eqTable = program->getEquateTable();
        if (eqTable) {
            for (auto* eq : eqTable->getEquates()) {
                if (!eq) continue;
                std::string eqName = escapeString(eq->getName());
                int64_t eqVal = eq->getValue();
                sql = "INSERT INTO equates (name, value) VALUES ('" + eqName + "', " + std::to_string(eqVal) + ")";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }
        }

        auto* relocTable = program->getRelocationTable();
        if (relocTable) {
            for (auto& r : relocTable->getRelocations()) {
                std::string rAddr = escapeString(r.getAddress().toString());
                long rType = r.getType();
                std::string rSym = escapeString(r.getSymbolName());
                sql = "INSERT INTO relocations (address, type, symbol_name) VALUES ('" +
                      rAddr + "', " + std::to_string(rType) + ", '" + rSym + "')";
                if (!execute(sql)) {
                    rollbackTransaction();
                    return false;
                }
            }
        }

        execute("DELETE FROM external_locations");
        execute("DELETE FROM source_files");
        execute("DELETE FROM int_range_maps");
        execute("DELETE FROM source_map_entries");
        execute("DELETE FROM program_register_values");
        execute("DELETE FROM program_register_default_values");

        auto* extMgr = dynamic_cast<ExternalManagerImpl*>(program->getExternalManager());
        if (extMgr) {
            auto extLocs = extMgr->getExternalLocations();
            for (auto* loc : extLocs) {
                if (!loc) continue;
                std::string libName = escapeString(loc->getLibraryName());
                std::string label = escapeString(loc->getLabel());
                std::string addrStr = escapeString(loc->getAddress().toString());
                sql = "INSERT INTO external_locations (library_name, label, address) VALUES ('" +
                      libName + "', '" + label + "', '" + addrStr + "')";
                if (!execute(sql)) { rollbackTransaction(); return false; }
            }
        }

        std::unordered_map<std::string, int64_t> sourceFileRowIds;
        auto* srcMgr = dynamic_cast<SourceFileManagerImpl*>(program->getSourceFileManager());
        if (srcMgr) {
            auto srcFiles = srcMgr->getSourceFiles();
            for (auto* sf : srcFiles) {
                if (!sf) continue;
                std::string path = escapeString(sf->getPath());
                std::string spec = escapeString(sf->getCompilerSpec());
                int idType = static_cast<int>(sf->getIdType());
                std::string idHex = toHexLiteral(sf->getIdentifier());
                sql = "INSERT INTO source_files (path, compiler_spec, id_type, id_bytes) VALUES ('" +
                      path + "', '" + spec + "', " + std::to_string(idType) + ", " + idHex + ")";
                if (!execute(sql)) { rollbackTransaction(); return false; }
                sourceFileRowIds[sf->getPath()] = lastInsertRowId();
            }

            for (const auto& entry : srcMgr->getSourceMapEntriesDirect()) {
                SourceFile* sf = entry.getSourceFile();
                int64_t fileId = 0;
                if (sf) {
                    auto it = sourceFileRowIds.find(sf->getPath());
                    if (it != sourceFileRowIds.end()) {
                        fileId = it->second;
                    }
                }
                int lineNum = entry.getLineNumber();
                std::string startAddr = escapeString(entry.getBaseAddress().toString());
                Address endAddr;
                if (entry.getLength() > 0) {
                    try {
                        endAddr = entry.getBaseAddress().addNoWrap(entry.getLength() - 1);
                    } catch (const AddressOverflowException&) {
                        auto genSpace = dynamic_cast<const GenericAddressSpace*>(entry.getBaseAddress().getAddressSpace());
                        uint64_t maxOffset = genSpace ? genSpace->getMaxOffset() : (entry.getBaseAddress().getAddressSpace()->getSize() == 64 ? -1LL : ((1ULL << entry.getBaseAddress().getAddressSpace()->getSize()) - 1));
                        endAddr = Address(entry.getBaseAddress().getAddressSpace(), maxOffset);
                    }
                } else {
                    endAddr = entry.getBaseAddress();
                }
                std::string endAddrStr = escapeString(endAddr.toString());
                uint64_t length = entry.getLength();

                sql = "INSERT INTO source_map_entries (file_id, line_number, start_address, end_address, length) VALUES (" +
                      std::to_string(fileId) + ", " + std::to_string(lineNum) + ", '" + startAddr + "', '" + endAddrStr + "', " +
                      std::to_string(length) + ")";
                if (!execute(sql)) { rollbackTransaction(); return false; }
            }
        }

        auto* propMgr = dynamic_cast<PropertyMapManagerImpl*>(program->getUsrPropertyManager());
        if (propMgr) {
            for (const auto& pair : propMgr->getIntRangeMaps()) {
                const auto& mapName = pair.first;
                const auto& irm = pair.second;
                if (!irm) continue;
                for (const auto& range : irm->getRanges()) {
                    std::string startStr = escapeString(range.start.toString());
                    std::string endStr = escapeString(range.end.toString());
                    sql = "INSERT INTO int_range_maps (map_name, start_address, end_address, value) VALUES ('" +
                          escapeString(mapName) + "', '" + startStr + "', '" + endStr + "', " +
                          std::to_string(range.value) + ")";
                    if (!execute(sql)) { rollbackTransaction(); return false; }
                }
            }
        }

        auto* ctx = dynamic_cast<ProgramContextImpl*>(program->getProgramContext());
        if (ctx) {
            // Save uint64 values
            for (const auto& pair : ctx->getUint64Values()) {
                const auto& key = pair.first;
                uint64_t val = pair.second;
                if (!key.reg) continue;
                std::string regName = escapeString(key.reg->getName());
                std::string startAddr = escapeString(key.start.toString());
                std::string endAddr = escapeString(key.end.toString());
                sql = "INSERT INTO program_register_values (register_name, start_address, end_address, value_bytes, uint64_value, is_uint64) VALUES ('" +
                      regName + "', '" + startAddr + "', '" + endAddr + "', NULL, " + std::to_string(val) + ", 1)";
                if (!execute(sql)) { rollbackTransaction(); return false; }
            }

            // Save RegisterValue values
            for (const auto& pair : ctx->getRegisterValues()) {
                const auto& key = pair.first;
                RegisterValue* rv = pair.second;
                if (!key.reg || !rv) continue;
                std::string regName = escapeString(key.reg->getName());
                std::string startAddr = escapeString(key.start.toString());
                std::string endAddr = escapeString(key.end.toString());
                std::string valHex = toHexLiteral(rv->getValue());
                sql = "INSERT INTO program_register_values (register_name, start_address, end_address, value_bytes, uint64_value, is_uint64) VALUES ('" +
                      regName + "', '" + startAddr + "', '" + endAddr + "', " + valHex + ", NULL, 0)";
                if (!execute(sql)) { rollbackTransaction(); return false; }
            }

            // Save default register values
            for (const auto& pair : ctx->getDefaultValues()) {
                const auto& key = pair.first;
                RegisterValue* rv = pair.second;
                if (!key.reg || !rv) continue;
                std::string regName = escapeString(key.reg->getName());
                std::string startAddr = escapeString(key.start.toString());
                std::string endAddr = escapeString(key.end.toString());
                std::string valHex = toHexLiteral(rv->getValue());
                sql = "INSERT INTO program_register_default_values (register_name, start_address, end_address, value_bytes) VALUES ('" +
                      regName + "', '" + startAddr + "', '" + endAddr + "', " + valHex + ")";
                if (!execute(sql)) { rollbackTransaction(); return false; }
            }
        }

        execute("DELETE FROM trees");
        execute("DELETE FROM tree_modules");
        execute("DELETE FROM tree_fragments");
        execute("DELETE FROM tree_relationships");
        execute("DELETE FROM tree_fragment_ranges");

        auto* treeMgr = program->getTreeManager();
        if (treeMgr) {
            for (const auto& treePair : treeMgr->getModules()) {
                const auto& treeName = treePair.first;
                const auto& mgr = treePair.second;
                if (!mgr) continue;

                long treeId = mgr->getTreeID();
                long modNum = mgr->getModificationNumber();

                sql = "INSERT INTO trees (id, name, modification_number) VALUES (" +
                      std::to_string(treeId) + ", '" + escapeString(treeName) + "', " + std::to_string(modNum) + ")";
                if (!execute(sql)) { rollbackTransaction(); return false; }

                for (const auto& modPair : mgr->getModules()) {
                    long modId = modPair.first;
                    const auto& mod = modPair.second;
                    if (!mod) continue;
                    sql = "INSERT INTO tree_modules (id, tree_id, name, comment) VALUES (" +
                          std::to_string(modId) + ", " + std::to_string(treeId) + ", '" +
                          escapeString(mod->getName()) + "', '" + escapeString(mod->getComment()) + "')";
                    if (!execute(sql)) { rollbackTransaction(); return false; }
                }

                for (const auto& fragPair : mgr->getFragments()) {
                    long fragId = fragPair.first;
                    const auto& frag = fragPair.second;
                    if (!frag) continue;
                    sql = "INSERT INTO tree_fragments (id, tree_id, name, comment) VALUES (" +
                          std::to_string(fragId) + ", " + std::to_string(treeId) + ", '" +
                          escapeString(frag->getName()) + "', '" + escapeString(frag->getComment()) + "')";
                    if (!execute(sql)) { rollbackTransaction(); return false; }

                    AddressRangeIterator* rangeIter = frag->getAddressRanges();
                    if (rangeIter) {
                        while (rangeIter->hasNext()) {
                            AddressRange range = rangeIter->next();
                            std::string startStr = escapeString(range.getMinAddress().toString());
                            std::string endStr = escapeString(range.getMaxAddress().toString());
                            sql = "INSERT INTO tree_fragment_ranges (tree_id, fragment_id, start_address, end_address) VALUES (" +
                                  std::to_string(treeId) + ", " + std::to_string(fragId) + ", '" + startStr + "', '" + endStr + "')";
                            if (!execute(sql)) {
                                delete rangeIter;
                                rollbackTransaction();
                                return false;
                            }
                        }
                        delete rangeIter;
                    }
                }

                for (const auto& modPair : mgr->getModules()) {
                    long parentID = modPair.first;
                    std::vector<long> childIDs = mgr->getChildrenIDs(parentID);
                    for (size_t i = 0; i < childIDs.size(); ++i) {
                        long childID = childIDs[i];
                        sql = "INSERT INTO tree_relationships (tree_id, parent_id, child_id, order_idx) VALUES (" +
                              std::to_string(treeId) + ", " + std::to_string(parentID) + ", " + std::to_string(childID) + ", " + std::to_string(i) + ")";
                        if (!execute(sql)) { rollbackTransaction(); return false; }
                    }
                }
            }
        }

        return commitTransaction();
    }

    bool loadProgram(ProgramDB* program) override {
        if (!program || !db_) return false;

        auto infoResult = query("SELECT name, language_id, compiler_spec_id FROM program_info LIMIT 1");
        if (infoResult.rowCount() == 0) return false;

        std::string progName = infoResult.rows[0][0];
        program->setName(progName);

        // Load memory blocks
        auto blocksResult = query("SELECT name, start_addr, size, is_initialized, "
                                  "is_read, is_write, is_execute, is_volatile FROM memory_blocks");
        auto* memory = dynamic_cast<DefaultMemory*>(program->getMemory());
        if (memory) {
            for (const auto& row : blocksResult.rows) {
                if (row.size() >= 8) {
                    std::string blockName = row[0];
                    std::string startAddrStr = row[1];
                    int64_t size = std::stoll(row[2]);
                    bool isInitialized = std::stoi(row[3]) != 0;
                    bool isRead = std::stoi(row[4]) != 0;
                    bool isWrite = std::stoi(row[5]) != 0;
                    bool isExecute = std::stoi(row[6]) != 0;
                    bool isVolatile = std::stoi(row[7]) != 0;

                    auto startOpt = program->getAddressFactory()->getAddress(startAddrStr);
                    if (startOpt.has_value()) {
                        Address startAddr = startOpt.value();
                        MemoryBlock* block = nullptr;
                        if (isInitialized) {
                            block = memory->createInitializedBlock(blockName, startAddr, size, 0, false);
                        } else {
                            block = memory->createUninitializedBlock(blockName, startAddr, size, false);
                        }
                        if (block) {
                            block->setRead(isRead);
                            block->setWrite(isWrite);
                            block->setExecute(isExecute);
                            block->setVolatile(isVolatile);
                        }
                    }
                }
            }
        }

        // Load namespaces
        auto* symTable = program->getSymbolTable();
        if (symTable) {
            struct RawNamespaceRow {
                long id;
                std::string name;
                long parent_id;
            };
            std::unordered_map<long, RawNamespaceRow> rawNsRows;
            auto nsResult = query("SELECT id, name, parent_id FROM namespaces");
            for (const auto& row : nsResult.rows) {
                if (row.size() >= 3) {
                    RawNamespaceRow r;
                    r.id = std::stol(row[0]);
                    r.name = row[1];
                    r.parent_id = std::stol(row[2]);
                    rawNsRows[r.id] = r;
                }
            }

            std::function<Namespace*(long)> resolveNs = [&](long id) -> Namespace* {
                if (id == 0 || id == Namespace::GLOBAL_NAMESPACE_ID) {
                    return symTable->getGlobalNamespace();
                }
                auto& existingMap = symTable->getNamespaces();
                auto itExist = existingMap.find(id);
                if (itExist != existingMap.end()) {
                    return itExist->second.get();
                }
                auto it = rawNsRows.find(id);
                if (it == rawNsRows.end()) {
                    return symTable->getGlobalNamespace();
                }
                const auto& r = it->second;
                Namespace* parentNs = resolveNs(r.parent_id);
                return symTable->addNamespaceWithId(r.id, r.name, parentNs);
            };

            for (const auto& pair : rawNsRows) {
                resolveNs(pair.first);
            }
        }

        // Load symbols
        auto symbolsResult = query("SELECT name, address, namespace_id, symbol_type, source_type, "
                                   "is_primary, is_external FROM symbols");
        if (symTable) {
            for (const auto& row : symbolsResult.rows) {
                if (row.size() >= 7) {
                    std::string symName = row[0];
                    std::string addrStr = row[1];
                    long nsId = std::stol(row[2]);
                    int sourceTypeVal = std::stoi(row[4]);
                    bool isPrimary = std::stoi(row[5]) != 0;
                    bool isExternal = std::stoi(row[6]) != 0;

                    auto addrOpt = program->getAddressFactory()->getAddress(addrStr);
                    if (addrOpt.has_value()) {
                        Address addr = addrOpt.value();
                        SourceType srcType = parseSourceType(sourceTypeVal);
                        
                        Namespace* ns = symTable->getGlobalNamespace();
                        if (nsId != 0) {
                            auto& nsMap = symTable->getNamespaces();
                            auto itNs = nsMap.find(nsId);
                            if (itNs != nsMap.end()) {
                                ns = itNs->second.get();
                            }
                        }

                        Symbol* sym = symTable->createLabel(addr, symName, ns, srcType);
                        if (sym) {
                            sym->setPrimary(isPrimary);
                            sym->setExternal(isExternal);
                        }
                    }
                }
            }
        }

        // Load functions
        // Migration: add missing columns if they don't exist (from old schema)
        execute("ALTER TABLE functions ADD COLUMN calling_convention TEXT");
        execute("ALTER TABLE functions ADD COLUMN return_type TEXT");
        execute("ALTER TABLE functions ADD COLUMN signature TEXT");
        execute("ALTER TABLE functions ADD COLUMN signature_source INTEGER DEFAULT 0");
        execute("ALTER TABLE functions ADD COLUMN is_constructor INTEGER DEFAULT 0");
        execute("ALTER TABLE functions ADD COLUMN is_destructor INTEGER DEFAULT 0");
        execute("ALTER TABLE functions ADD COLUMN call_fixup TEXT");

        // Load functions
        auto functionsResult = query("SELECT name, entry_point, calling_convention, return_type, "
                                      "signature, signature_source, is_thunk, is_external, "
                                      "has_no_return, is_inline, is_constructor, is_destructor, "
                                      "call_fixup, stack_frame_size FROM functions");
        auto* funcMgr = program->getFunctionManager();
        if (funcMgr) {
            for (const auto& row : functionsResult.rows) {
                if (row.size() >= 14) {
                    std::string funcName = row[0];
                    std::string entryPointStr = row[1];
                    std::string ccName = row[2];
                    std::string retTypeName = row[3];
                    std::string sigStr = row[4];
                    int sigSourceVal = std::stoi(row[5]);
                    bool isThunk = std::stoi(row[6]) != 0;
                    bool isExternal = std::stoi(row[7]) != 0;
                    bool hasNoReturn = std::stoi(row[8]) != 0;
                    bool isInline = std::stoi(row[9]) != 0;
                    bool isConstructor = std::stoi(row[10]) != 0;
                    bool isDestructor = std::stoi(row[11]) != 0;
                    std::string callFixup = row[12];
                    int stackFrameSize = std::stoi(row[13]);

                    auto entryOpt = program->getAddressFactory()->getAddress(entryPointStr);
                    if (entryOpt.has_value()) {
                        Address entry = entryOpt.value();
                        AddressSet body(entry, entry);
                        Function* func = funcMgr->createFunction(funcName, entry, body, SourceType::USER_DEFINED);
                        if (func) {
                            func->setThunk(isThunk);
                            func->setExternal(isExternal);
                            func->setHasNoReturn(hasNoReturn);
                            func->setInline(isInline);
                            func->setStackFrameSize(stackFrameSize);
                            func->setConstructor(isConstructor);
                            func->setDestructor(isDestructor);
                            if (!callFixup.empty()) func->setCallFixup(callFixup);

                            // Restore signature source
                            func->setSignatureSource(static_cast<SignatureSource>(sigSourceVal));

                            // Restore calling convention
                            if (!ccName.empty()) {
                                PrototypeModel* cc = funcMgr->getCallingConvention(ccName);
                                if (cc) func->setCallingConvention(cc);
                            }

                            // Restore return type
                            if (!retTypeName.empty()) {
                                DataTypeManager* dtm = program->getDataTypeManager();
                                if (dtm) {
                                    DataType* retDt = dtm->getDataType(CategoryPath::ROOT(), retTypeName);
                                    if (retDt) func->setReturnType(retDt);
                                }
                            }

                            // Restore signature
                            if (!sigStr.empty()) {
                                FunctionSignatureImpl* sig = new FunctionSignatureImpl(funcName);
                                func->setSignature(sig);
                            }

                            // Load variables and parameters for this function (Wave 67)
                            auto* dtMgr = program->getDataTypeManager();
                            std::string varSql = "SELECT var_kind, name, datatype_id, storage, comment, source_type, "
                                                 "ordinal, first_use_offset, auto_param_type FROM function_variables "
                                                 "WHERE function_entry = '" + escapeString(entryPointStr) + "'";
                            auto varResult = query(varSql);
                            for (const auto& varRow : varResult.rows) {
                                if (varRow.size() >= 9) {
                                    std::string varKind = varRow[0];
                                    std::string varName = varRow[1];
                                    long dtId = std::stol(varRow[2]);
                                    std::string storageStr = varRow[3];
                                    std::string comment = varRow[4];
                                    SourceType sourceType = static_cast<SourceType>(std::stoi(varRow[5]));
                                    int ordinal = std::stoi(varRow[6]);
                                    int firstUseOffset = std::stoi(varRow[7]);
                                    int autoParamTypeVal = std::stoi(varRow[8]);

                                    DataType* dt = nullptr;
                                    if (dtMgr && dtId != -1) {
                                        dt = dtMgr->getDataType(dtId);
                                    }
                                    VariableStorage storage = VariableStorage::deserialize(program, storageStr);

                                    if (varKind == "local") {
                                        auto* localVal = new LocalVariableImpl(varName, firstUseOffset, dt, storage, program, sourceType);
                                        if (!comment.empty()) {
                                            localVal->setComment(comment);
                                        }
                                        func->addLocalVariable(localVal);
                                    }
                                    else if (varKind == "parameter") {
                                        auto* param = new ParameterImpl(varName, ordinal, dt, storage, program, sourceType);
                                        if (!comment.empty()) {
                                            param->setComment(comment);
                                        }
                                        func->addParameter(param);
                                    }
                                    else if (varKind == "auto_parameter") {
                                        AutoParameterType autoType = static_cast<AutoParameterType>(autoParamTypeVal);
                                        auto* param = new AutoParameterImpl(dt, ordinal, storage, autoType, program);
                                        func->addParameter(param);
                                    }
                                    else if (varKind == "return_parameter") {
                                        auto* param = new ReturnParameterImpl(dt, storage, program);
                                        func->addParameter(param);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        auto* tagMgr = program->getFunctionTagManager();
        if (tagMgr) {
            auto tagResult = query("SELECT id, name, comment FROM function_tags");
            for (const auto& row : tagResult.rows) {
                if (row.size() >= 3) {
                    long id = std::stol(row[0]);
                    std::string tagName = row[1];
                    std::string tagComment = row[2];
                    auto* tagMgrImpl = dynamic_cast<FunctionTagManagerImpl*>(tagMgr);
                    if (tagMgrImpl) {
                        tagMgrImpl->addTagWithId(id, tagName, tagComment);
                    }
                }
            }
        }

        if (tagMgr) {
            auto mappingResult = query("SELECT function_entry, tag_id FROM function_tag_mappings");
            auto* funcMgr = program->getFunctionManager();
            if (funcMgr) {
                for (const auto& row : mappingResult.rows) {
                    if (row.size() >= 2) {
                        std::string entryPointStr = row[0];
                        long tagId = std::stol(row[1]);
                        auto entryOpt = program->getAddressFactory()->getAddress(entryPointStr);
                        if (entryOpt.has_value()) {
                            auto* func = funcMgr->getFunctionAt(entryOpt.value());
                            auto* tag = tagMgr->getFunctionTag(tagId);
                            if (func && tag) {
                                func->addTagDirect(tag);
                            }
                        }
                    }
                }
            }
        }

        auto* refMgr = program->getReferenceManager();
        if (refMgr) {
            auto refsResult = query("SELECT from_addr, to_addr, ref_type, op_index FROM \"references\"");
            for (const auto& row : refsResult.rows) {
                if (row.size() >= 4) {
                    auto fromOpt = program->getAddressFactory()->getAddress(row[0]);
                    auto toOpt = program->getAddressFactory()->getAddress(row[1]);
                    if (fromOpt.has_value() && toOpt.has_value()) {
                        int refTypeVal = std::stoi(row[2]);
                        const RefType* rtype = &RefTypes::DATA;
                        if (refTypeVal == RefType::__READ) rtype = &RefTypes::READ;
                        else if (refTypeVal == RefType::__WRITE) rtype = &RefTypes::WRITE;
                        else if (refTypeVal == RefType::__READ_WRITE) rtype = &RefTypes::READ_WRITE;
                        else if (refTypeVal == RefType::__UNCONDITIONAL_CALL) rtype = &RefTypes::UNCONDITIONAL_CALL;
                        else if (refTypeVal == RefType::__UNCONDITIONAL_JUMP) rtype = &RefTypes::UNCONDITIONAL_JUMP;
                        else if (refTypeVal == RefType::__CONDITIONAL_JUMP) rtype = &RefTypes::CONDITIONAL_JUMP;
                        else if (refTypeVal == RefType::__FALL_THROUGH) rtype = &RefTypes::FALL_THROUGH;
                        int opIdx = std::stoi(row[3]);
                        refMgr->addMemoryReference(fromOpt.value(), toOpt.value(), rtype, SourceType::IMPORTED, opIdx);
                    }
                }
            }
        }

        auto* bmMgr = program->getBookmarkManager();
        if (bmMgr) {
            auto bmResult = query("SELECT address, type, description FROM bookmarks");
            for (const auto& row : bmResult.rows) {
                if (row.size() >= 3) {
                    auto addrOpt = program->getAddressFactory()->getAddress(row[0]);
                    if (addrOpt.has_value()) {
                        bmMgr->setBookmark(addrOpt.value(), row[1], row[2]);
                    }
                }
            }
        }

        auto commentsResult = query("SELECT address, comment_type, text FROM comments");
        auto* listing = program->getListing();
        if (listing) {
            for (const auto& row : commentsResult.rows) {
                if (row.size() >= 3) {
                    auto addrOpt = program->getAddressFactory()->getAddress(row[0]);
                    if (addrOpt.has_value()) {
                        Address addr = addrOpt.value();
                        int commentTypeVal = std::stoi(row[1]);
                        std::string commentText = row[2];
                        CodeUnit* cu = listing->getCodeUnitAt(addr);
                        if (cu) {
                            if (commentTypeVal == static_cast<int>(Comment::Type::EOL_COMMENT)) {
                                cu->setComment(commentText);
                            } else if (commentTypeVal == static_cast<int>(Comment::Type::PRE_COMMENT)) {
                                cu->setPreComment(commentText);
                            } else if (commentTypeVal == static_cast<int>(Comment::Type::POST_COMMENT)) {
                                cu->setPostComment(commentText);
                            } else if (commentTypeVal == static_cast<int>(Comment::Type::PLATE_COMMENT)) {
                                cu->setPlateComment(commentText);
                            }
                        }
                    }
                }
            }
        }

        auto* eqTable = program->getEquateTable();
        if (eqTable) {
            auto equatesResult = query("SELECT name, value FROM equates");
            for (const auto& row : equatesResult.rows) {
                if (row.size() >= 2) {
                    std::string eqName = row[0];
                    int64_t eqValue = std::stoll(row[1]);
                    eqTable->createEquate(eqName, eqValue);
                }
            }
        }

        auto* relocTable = dynamic_cast<RelocationTableImpl*>(program->getRelocationTable());
        if (relocTable) {
            auto relocsResult = query("SELECT address, type, symbol_name FROM relocations");
            for (const auto& row : relocsResult.rows) {
                if (row.size() >= 3) {
                    auto addrOpt = program->getAddressFactory()->getAddress(row[0]);
                    if (addrOpt.has_value()) {
                        long type = std::stol(row[1]);
                        std::string symName = row[2];
                        relocTable->addRelocation(addrOpt.value(), type, symName);
                    }
                }
            }
        }

        // Wave 59: DataTypeManager persistence logic (Load)
        auto* dtMgr = dynamic_cast<DataTypeManagerImpl*>(program->getDataTypeManager());
        if (dtMgr) {
            struct RawDataTypeRow {
                long id;
                std::string category;
                std::string name;
                std::string type_kind;
                int length;
                long referred_type_id; // -1 if NULL
                int array_element_count; // -1 if NULL
            };

            std::unordered_map<long, RawDataTypeRow> rawRows;
            auto datatypesResult = query("SELECT id, category, name, type_kind, length, referred_type_id, array_element_count FROM datatypes");
            for (const auto& row : datatypesResult.rows) {
                if (row.size() >= 7) {
                    RawDataTypeRow r;
                    r.id = std::stol(row[0]);
                    r.category = row[1];
                    r.name = row[2];
                    r.type_kind = row[3];
                    r.length = std::stoi(row[4]);
                    r.referred_type_id = row[5].empty() || row[5] == "NULL" ? -1 : std::stol(row[5]);
                    r.array_element_count = row[6].empty() || row[6] == "NULL" ? -1 : std::stoi(row[6]);
                    rawRows[r.id] = r;
                }
            }

            // Recursive resolver lambda
            std::function<DataType*(long)> resolveType = [&](long id) -> DataType* {
                // 1. Check if already registered/resolved (including built-ins)
                if (auto* existing = dtMgr->getDataType(id)) {
                    return existing;
                }

                // 2. Check if in rawRows
                auto it = rawRows.find(id);
                if (it == rawRows.end()) {
                    return nullptr;
                }

                const auto& r = it->second;
                CategoryPath path(r.category);

                if (r.type_kind == "structure") {
                    auto* structDt = new StructureDataType(path, r.name, 0, dtMgr);
                    dtMgr->addDataTypeWithId(structDt, id);
                    return structDt;
                } else if (r.type_kind == "union") {
                    auto* unionDt = new UnionDataType(path, r.name, dtMgr);
                    dtMgr->addDataTypeWithId(unionDt, id);
                    return unionDt;
                } else if (r.type_kind == "enum") {
                    auto* enumDt = new EnumDataType(path, r.name, r.length, dtMgr);
                    dtMgr->addDataTypeWithId(enumDt, id);
                    return enumDt;
                } else if (r.type_kind == "typedef") {
                    auto* refType = resolveType(r.referred_type_id);
                    if (refType) {
                        auto* typedefDt = new TypedefDataType(path, r.name, refType, dtMgr);
                        dtMgr->addDataTypeWithId(typedefDt, id);
                        return typedefDt;
                    }
                    return nullptr;
                } else if (r.type_kind == "pointer") {
                    auto* refType = resolveType(r.referred_type_id);
                    if (refType) {
                        auto* pointerDt = new PointerDataType(refType, r.length, dtMgr);
                        dtMgr->addDataTypeWithId(pointerDt, id);
                        return pointerDt;
                    }
                    return nullptr;
                } else if (r.type_kind == "array") {
                    auto* refType = resolveType(r.referred_type_id);
                    if (refType && r.array_element_count > 0) {
                        auto* arrayDt = new ArrayDataType(refType, r.array_element_count, r.length / r.array_element_count, dtMgr);
                        dtMgr->addDataTypeWithId(arrayDt, id);
                        return arrayDt;
                    }
                    return nullptr;
                } else {
                    return nullptr;
                }
            };

            // Loop to resolve all shells
            for (const auto& pair : rawRows) {
                resolveType(pair.first);
            }

            // Phase 2: Populate components
            auto componentsResult = query("SELECT parent_type_id, member_type_id, member_name, offset, length FROM datatype_components ORDER BY id ASC");
            for (const auto& row : componentsResult.rows) {
                if (row.size() >= 5) {
                    long parentId = std::stol(row[0]);
                    long memberId = std::stol(row[1]);
                    std::string memberName = row[2];
                    int offset = std::stoi(row[3]);
                    int length = std::stoi(row[4]);

                    auto* parentDt = dtMgr->getDataType(parentId);
                    auto* memberDt = dtMgr->getDataType(memberId);
                    if (parentDt && memberDt) {
                        if (auto* structDt = dynamic_cast<StructureDataType*>(parentDt)) {
                            structDt->insertAtOffset(offset, memberDt, length, memberName, "");
                        } else if (auto* unionDt = dynamic_cast<UnionDataType*>(parentDt)) {
                            unionDt->add(memberDt, length, memberName, "");
                        }
                    }
                }
            }

            // Phase 2: Populate enum values
            auto enumValuesResult = query("SELECT enum_type_id, name, value FROM enum_values ORDER BY id ASC");
            for (const auto& row : enumValuesResult.rows) {
                if (row.size() >= 3) {
                    long enumId = std::stol(row[0]);
                    std::string name = row[1];
                    long long value = std::stoll(row[2]);

                    if (auto* enumDt = dynamic_cast<EnumDataType*>(dtMgr->getDataType(enumId))) {
                        enumDt->add(name, value);
                    }
                }
            }
        }

        auto* extMgr = dynamic_cast<ExternalManagerImpl*>(program->getExternalManager());
        if (extMgr) {
            auto extResult = query("SELECT library_name, label, address FROM external_locations");
            for (const auto& row : extResult.rows) {
                if (row.size() >= 3) {
                    std::string libName = row[0];
                    std::string label = row[1];
                    Address addr;
                    if (!row[2].empty()) {
                        auto addrOpt = program->getAddressFactory()->getAddress(row[2]);
                        if (addrOpt.has_value()) addr = addrOpt.value();
                    }
                    extMgr->addExternalLocation(libName, label, addr);
                }
            }
        }

        std::unordered_map<long, SourceFile*> dbIdToSourceFile;
        auto* srcMgr = dynamic_cast<SourceFileManagerImpl*>(program->getSourceFileManager());
        if (srcMgr) {
            auto srcResult = query("SELECT id, path, compiler_spec, id_type, hex(id_bytes) FROM source_files");
            for (const auto& row : srcResult.rows) {
                if (row.size() >= 5) {
                    long dbId = std::stol(row[0]);
                    std::string path = row[1];
                    std::string compSpec = row[2];
                    int idTypeVal = std::stoi(row[3]);
                    std::vector<uint8_t> idBytes = parseHexBytes(row[4]);
                    
                    SourceFile sf(path, static_cast<SourceFileIdType>(idTypeVal), idBytes, compSpec);
                    srcMgr->addSourceFile(&sf);
                    
                    SourceFile* addedSf = srcMgr->getSourceFile(path);
                    if (addedSf) {
                        dbIdToSourceFile[dbId] = addedSf;
                    }
                }
            }

            auto entriesResult = query("SELECT file_id, line_number, start_address, length FROM source_map_entries");
            for (const auto& row : entriesResult.rows) {
                if (row.size() >= 4) {
                    long fileId = std::stol(row[0]);
                    int lineNum = std::stoi(row[1]);
                    std::string startAddrStr = row[2];
                    uint64_t length = std::stoull(row[3]);

                    auto addrOpt = program->getAddressFactory()->getAddress(startAddrStr);
                    if (addrOpt.has_value()) {
                        Address startAddr = addrOpt.value();
                        SourceFile* sf = nullptr;
                        auto it = dbIdToSourceFile.find(fileId);
                        if (it != dbIdToSourceFile.end()) {
                            sf = it->second;
                        }
                        if (sf) {
                            srcMgr->addSourceMapEntryDirect(SourceMapEntry(sf, lineNum, startAddr, length));
                        }
                    }
                }
            }
        }

        auto* ctx = dynamic_cast<ProgramContextImpl*>(program->getProgramContext());
        if (ctx) {
            ctx->clearAll();
            auto regValResult = query("SELECT register_name, start_address, end_address, hex(value_bytes), uint64_value, is_uint64 FROM program_register_values");
            for (const auto& row : regValResult.rows) {
                if (row.size() >= 6) {
                    std::string regName = row[0];
                    std::string startAddrStr = row[1];
                    std::string endAddrStr = row[2];
                    std::string valBytesHex = row[3];
                    
                    auto startOpt = program->getAddressFactory()->getAddress(startAddrStr);
                    auto endOpt = program->getAddressFactory()->getAddress(endAddrStr);
                    Register* reg = program->getLanguage()->getRegister(regName);
                    
                    if (startOpt.has_value() && endOpt.has_value() && reg) {
                        Address start = startOpt.value();
                        Address end = endOpt.value();
                        bool isUint64 = std::stoi(row[5]) != 0;
                        if (isUint64) {
                            uint64_t uint64Val = std::stoull(row[4]);
                            ctx->setValue(reg, uint64Val, start, end);
                        } else {
                            std::vector<uint8_t> valBytes = parseHexBytes(valBytesHex);
                            RegisterValue rv(reg, valBytes);
                            ctx->setRegisterValue(&rv, start, end);
                        }
                    }
                }
            }

            auto regDefaultResult = query("SELECT register_name, start_address, end_address, hex(value_bytes) FROM program_register_default_values");
            for (const auto& row : regDefaultResult.rows) {
                if (row.size() >= 4) {
                    std::string regName = row[0];
                    std::string startAddrStr = row[1];
                    std::string endAddrStr = row[2];
                    std::string valBytesHex = row[3];
                    
                    auto startOpt = program->getAddressFactory()->getAddress(startAddrStr);
                    auto endOpt = program->getAddressFactory()->getAddress(endAddrStr);
                    Register* reg = program->getLanguage()->getRegister(regName);
                    
                    if (startOpt.has_value() && endOpt.has_value() && reg) {
                        Address start = startOpt.value();
                        Address end = endOpt.value();
                        std::vector<uint8_t> valBytes = parseHexBytes(valBytesHex);
                        RegisterValue rv(reg, valBytes);
                        ctx->setDefaultValue(&rv, start, end);
                    }
                }
            }
        }

        auto* propMgr = dynamic_cast<PropertyMapManagerImpl*>(program->getUsrPropertyManager());
        if (propMgr) {
            auto irmResult = query("SELECT map_name, start_address, end_address, value FROM int_range_maps ORDER BY id ASC");
            for (const auto& row : irmResult.rows) {
                if (row.size() >= 4) {
                    std::string mapName = row[0];
                    IntRangeMap* irm = propMgr->getIntRangeMap(mapName);
                    if (!irm) irm = propMgr->createIntRangeMap(mapName);
                    auto startOpt = program->getAddressFactory()->getAddress(row[1]);
                    auto endOpt = program->getAddressFactory()->getAddress(row[2]);
                    if (startOpt.has_value() && endOpt.has_value()) {
                        irm->setValue(startOpt.value(), endOpt.value(), std::stoll(row[3]));
                    }
                }
            }
        }

        // Load trees
        auto* treeMgr = program->getTreeManager();
        if (treeMgr) {
            treeMgr->clearCache(true);

            long maxTreeId = 1;
            auto treesResult = query("SELECT id, name, modification_number FROM trees ORDER BY id ASC");
            for (const auto& treeRow : treesResult.rows) {
                if (treeRow.size() >= 3) {
                    long treeId = std::stol(treeRow[0]);
                    std::string treeName = treeRow[1];
                    long modNum = std::stol(treeRow[2]);

                    if (treeId >= maxTreeId) {
                        maxTreeId = treeId + 1;
                    }

                    auto mgr = std::make_unique<ModuleManager>(treeMgr, treeId, treeName);
                    mgr->setModificationNumber(modNum);

                    // Load modules for this tree
                    std::string modQuery = "SELECT id, name, comment FROM tree_modules WHERE tree_id = " + std::to_string(treeId);
                    auto modsResult = query(modQuery);
                    for (const auto& modRow : modsResult.rows) {
                        if (modRow.size() >= 3) {
                            long modId = std::stol(modRow[0]);
                            std::string modName = modRow[1];
                            std::string modComment = modRow[2];
                            mgr->loadModule(modId, modName, modComment);
                        }
                    }

                    // Load fragments for this tree
                    std::string fragQuery = "SELECT id, name, comment FROM tree_fragments WHERE tree_id = " + std::to_string(treeId);
                    auto fragsResult = query(fragQuery);
                    for (const auto& fragRow : fragsResult.rows) {
                        if (fragRow.size() >= 3) {
                            long fragId = std::stol(fragRow[0]);
                            std::string fragName = fragRow[1];
                            std::string fragComment = fragRow[2];
                            auto* frag = mgr->loadFragment(fragId, fragName, fragComment);

                            // Load ranges for this fragment
                            std::string rangeQuery = "SELECT start_address, end_address FROM tree_fragment_ranges WHERE tree_id = " +
                                                     std::to_string(treeId) + " AND fragment_id = " + std::to_string(fragId);
                            auto rangesResult = query(rangeQuery);
                            for (const auto& rangeRow : rangesResult.rows) {
                                if (rangeRow.size() >= 2) {
                                    auto startOpt = program->getAddressFactory()->getAddress(rangeRow[0]);
                                    auto endOpt = program->getAddressFactory()->getAddress(rangeRow[1]);
                                    if (startOpt.has_value() && endOpt.has_value()) {
                                        frag->addRange(startOpt.value(), endOpt.value());
                                    }
                                }
                            }
                        }
                    }

                    // Load relationships for this tree, ordering by order_idx
                    std::string relQuery = "SELECT parent_id, child_id FROM tree_relationships WHERE tree_id = " +
                                           std::to_string(treeId) + " ORDER BY order_idx ASC";
                    auto relsResult = query(relQuery);
                    for (const auto& relRow : relsResult.rows) {
                        if (relRow.size() >= 2) {
                            long parentId = std::stol(relRow[0]);
                            long childId = std::stol(relRow[1]);
                            mgr->addRelationship(parentId, childId);
                        }
                    }

                    treeMgr->getModulesMutable()[treeName] = std::move(mgr);
                }
            }
            treeMgr->setNextTreeID(maxTreeId);
        }

        return true;
    }

    std::string getLastError() const override { return lastError_; }

private:
    sqlite3* db_;
    bool inTransaction_;
    std::string lastError_;
};

std::unique_ptr<DatabaseAdapter> createDatabaseAdapter() {
    return std::make_unique<SQLiteDatabaseAdapter>();
}

} // namespace ghidra
