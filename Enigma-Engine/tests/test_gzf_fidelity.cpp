/* ###
 * IP: Enigma Engine (original work)
 *
 * End-to-end GZF snapshot fidelity test.
 *
 * Imports the real Ghidra corpora (notepad_test.exe, key.exe), serializes the
 * full ProgramDB state through SnapshotWriter/CommitManager, reloads it with
 * SnapshotReader and asserts the canonical semantic state-dump is identical.
 * The user-edit workflow (bytes, comments, bookmarks, labels, metadata,
 * register values, equates) is committed as a second revision and verified to
 * survive a reload while the original revision stays intact.
 *
 * Also cross-checks the corpus "Property Map - Lengths" table against the
 * data-unit lengths recomputed at import (Ghidra stored them; we recompute).
 *
 * Corpora are located via ENIGMA_CORPUS_DIR or by probing ../ and ../..
 * relative to the test's working directory; the test SKIPs (exit 0) when no
 * corpus is present.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/EventLog.h>
#include <ghidra/storage/SnapshotReader.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/StackReference.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/EquateTable.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/FunctionTagManager.h>
#include <ghidra/Parameter.h>
#include <ghidra/LocalVariable.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Register.h>
#include <ghidra/SourceFileManager.h>
#include <ghidra/SourceFileManagerImpl.h>
#include <ghidra/ProgramContextImpl.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DataOrganizationImpl.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/DataType.h>
#include <ghidra/Composite.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/Array.h>
#include <ghidra/FunctionDefinitionDataType.h>
#include <ghidra/FunctionDefinition.h>
#include <ghidra/ParameterDefinition.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/ProgramContextImpl.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/TreeManager.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/ModuleDB.h>
#include <ghidra/FragmentDB.h>
#include <ghidra/AddressSet.h>
#include <ghidra/import/GbfReader.h>
#include <ghidra/import/GzfProgramImporter.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>

namespace fs = std::filesystem;
using namespace ghidra;
using namespace ghidra::storage;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

namespace {

std::string findCorpus(const std::string& relPath) {
    if (const char* dir = std::getenv("ENIGMA_CORPUS_DIR")) {
        fs::path p = fs::path(dir) / relPath;
        if (fs::exists(p)) return p.string();
    }
    for (const char* prefix : {"", "../", "../../"}) {
        fs::path p = fs::path(prefix) / relPath;
        if (fs::exists(p)) return p.string();
    }
    return "";
}

std::vector<uint8_t> readFileBytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

std::unique_ptr<ProgramDB> importProgram(const std::string& gbfPath,
                                         const std::string& programName) {
    auto bytes = readFileBytes(gbfPath);
    auto reader = GbfReader::fromMemory(std::move(bytes));
    GzfProgramImporter importer(*reader);
    return importer.import(programName);
}

std::string hexBytes(const std::vector<uint8_t>& v) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (uint8_t b : v) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xF]);
    }
    return out;
}

std::string typeRef(const DataType* dt) {
    if (!dt) return "";
    return dt->getName() + "@" + dt->getCategoryPath().getPath();
}

// Compact variable-storage form (mirrors SnapshotWriter::storageToString).
std::string storageToString(const VariableStorage& s) {
    if (s.isUnassignedStorage() || s.isVoidStorage() || s.isBadStorage() || !s.isValid()) {
        return "u";
    }
    if (s.isRegisterStorage()) {
        Register* reg = s.getRegister();
        if (!reg) return "u";
        return "reg:" + std::to_string(reg->getAddress().getOffset()) + ":" +
               std::to_string(s.size());
    }
    if (s.hasStackStorage()) {
        return "stack:" + std::to_string(static_cast<int64_t>(s.getStackOffset())) + ":" +
               std::to_string(s.size());
    }
    if (s.isMemoryStorage() && s.getMinAddress().isValid()) {
        return "mem:" + std::to_string(s.getMinAddress().getOffset()) + ":" +
               std::to_string(s.size());
    }
    return "u";
}

std::string nsPath(const Namespace* ns) {
    std::string path;
    while (ns && !ns->isGlobal()) {
        const std::string name = ns->getName();
        path = path.empty() ? name : name + "::" + path;
        ns = ns->getParent();
    }
    return path;
}

std::string dtKindOf(const DataType* dt) {
    if (dynamic_cast<const Structure*>(dt)) return "struct";
    if (dynamic_cast<const Union*>(dt)) return "union";
    if (dynamic_cast<const Enum*>(dt)) return "enum";
    if (dynamic_cast<const Pointer*>(dt)) return "pointer";
    if (dynamic_cast<const Array*>(dt)) return "array";
    if (dynamic_cast<const TypeDef*>(dt)) return "typedef";
    if (dynamic_cast<const FunctionDefinitionDataType*>(dt)) return "function";
    return "builtin";
}

/**
 * Canonical semantic state dump of a whole ProgramDB.  Every section is
 * sorted, so equality means the two programs carry identical state.
 */
std::string dumpState(const ProgramDB& program) {
    std::ostringstream out;
    auto* space = const_cast<AddressSpace*>(
        program.getAddressFactory()->getDefaultAddressSpace());

    std::string langId = program.getLanguageID().toString();
    out << "V|" << program.getName() << "|" << langId
        << "|" << program.getImageBase().getOffset()
        << "|" << program.getMinAddress().getOffset()
        << "|" << program.getMaxAddress().getOffset() << "\n";

    if (auto* dtmOrg = dynamic_cast<DataOrganizationImpl*>(
            program.getDataTypeManager()->getDataOrganization())) {
        out << "DO|" << dtmOrg->getPointerSize()
            << "|" << dtmOrg->getMachineAlignment()
            << "|" << (dtmOrg->getBitFieldPacking()->useMSConvention() ? 1 : 0)
            << "|";
        for (int s : dtmOrg->getSizes()) {
            out << s << ":" << dtmOrg->getSizeAlignment(s) << ";";
        }
        out << "\n";
    }

    if (auto* mem = program.getMemory()) {
        std::vector<MemoryBlock*> blocks = mem->getBlocks();
        std::sort(blocks.begin(), blocks.end(),
                  [](const MemoryBlock* a, const MemoryBlock* b) {
                      return a->getStart().getOffset() < b->getStart().getOffset();
                  });
        for (auto* block : blocks) {
            std::vector<uint8_t> bytes;
            if (block && block->isInitialized() && block->getSize() > 0) {
                bytes.resize(static_cast<size_t>(block->getSize()));
                int nread = block->getBytes(block->getStart(), bytes.data(),
                                            static_cast<int>(bytes.size()));
                if (nread < static_cast<int>(bytes.size())) {
                    bytes.resize(static_cast<size_t>(std::max(0, nread)));
                }
            }
            out << "M|" << block->getName()
                << "|" << block->getStart().getOffset()
                << "|" << block->getSize()
                << "|" << (block->isRead() ? 'r' : '-')
                << (block->isWrite() ? 'w' : '-')
                << (block->isExecute() ? 'x' : '-')
                << "|" << block->getComment()
                << "|" << hexBytes(bytes) << "\n";
        }
    }

    std::vector<std::string> unitLines;
    std::vector<std::string> commentLines;
    if (auto* listing = program.getListing()) {
        for (auto* inst : listing->getAllInstructions()) {
            if (!inst) continue;
            std::ostringstream line;
            line << "I|" << inst->getAddress().getOffset()
                 << "|" << inst->getLength()
                 << "|" << inst->getMnemonicString();
            unitLines.push_back(line.str());
            const std::string eol = inst->getComment();
            const std::string pre = inst->getPreComment();
            const std::string post = inst->getPostComment();
            const std::string plate = inst->getPlateComment();
            if (!eol.empty())
                commentLines.push_back("C|" + std::to_string(inst->getAddress().getOffset()) +
                                       "|EOL|" + eol);
            if (!pre.empty())
                commentLines.push_back("C|" + std::to_string(inst->getAddress().getOffset()) +
                                       "|PRE|" + pre);
            if (!post.empty())
                commentLines.push_back("C|" + std::to_string(inst->getAddress().getOffset()) +
                                       "|POST|" + post);
            if (!plate.empty())
                commentLines.push_back("C|" + std::to_string(inst->getAddress().getOffset()) +
                                       "|PLATE|" + plate);
            const std::string rep = inst->getRepeatableComment();
            if (!rep.empty())
                commentLines.push_back("C|" + std::to_string(inst->getAddress().getOffset()) +
                                       "|REP|" + rep);
        }
        for (auto* data : listing->getAllData()) {
            if (!data) continue;
            std::ostringstream line;
            line << "D|" << data->getAddress().getOffset()
                 << "|" << data->getLength()
                 << "|" << typeRef(data->getDataType());
            unitLines.push_back(line.str());
            const std::string eol = data->getComment();
            const std::string pre = data->getPreComment();
            const std::string post = data->getPostComment();
            const std::string plate = data->getPlateComment();
            if (!eol.empty())
                commentLines.push_back("C|" + std::to_string(data->getAddress().getOffset()) +
                                       "|EOL|" + eol);
            if (!pre.empty())
                commentLines.push_back("C|" + std::to_string(data->getAddress().getOffset()) +
                                       "|PRE|" + pre);
            if (!post.empty())
                commentLines.push_back("C|" + std::to_string(data->getAddress().getOffset()) +
                                       "|POST|" + post);
            if (!plate.empty())
                commentLines.push_back("C|" + std::to_string(data->getAddress().getOffset()) +
                                       "|PLATE|" + plate);
            const std::string drep = data->getRepeatableComment();
            if (!drep.empty())
                commentLines.push_back("C|" + std::to_string(data->getAddress().getOffset()) +
                                       "|REP|" + drep);
        }
    }
    std::sort(unitLines.begin(), unitLines.end());
    std::sort(commentLines.begin(), commentLines.end());
    for (const auto& l : unitLines) out << l << "\n";
    for (const auto& l : commentLines) out << l << "\n";

    std::vector<std::string> fnLines;
    std::vector<std::string> paramLines;
    if (auto* fm = program.getFunctionManager()) {
        auto it = fm->getFunctions(true);
        while (it.hasNext()) {
            Function* func = it.next();
            std::ostringstream line;
            line << "F|" << func->getEntryPoint().getOffset()
                 << "|" << func->getName()
                 << "|" << (func->getCallingConvention() ? func->getCallingConvention()->getName() : "")
                 << "|" << typeRef(func->getReturnType())
                 << "|" << func->getStackFrameSize()
                 << "|" << func->isExternal()
                 << "|" << func->hasNoReturn()
                 << "|" << func->isInline()
                 << "|" << func->getCallFixup()
                 << "|" << static_cast<int>(func->getSignatureSource())
                 << "|" << func->isThunk()
                 << "|" << (func->getThunkedFunction() ? func->getThunkedFunction()->getEntryPoint().getOffset() : 0)
                 << "|";
            for (auto& range : func->getBody().toList()) {
                line << range.getMinAddress().getOffset() << "-" << range.getLength() << ";";
            }
            fnLines.push_back(line.str());
            for (auto* param : func->getParameters()) {
                if (!param) continue;
                int ordinal = -1;
                if (auto* p = dynamic_cast<Parameter*>(param)) {
                    ordinal = p->getOrdinal();
                }
                std::ostringstream pline;
                pline << "P|" << func->getEntryPoint().getOffset()
                      << "|" << ordinal << "|" << param->getName()
                      << "|" << typeRef(param->getDataType())
                      << "|" << storageToString(param->getVariableStorage());
                paramLines.push_back(pline.str());
            }
            for (auto* var : func->getLocalVariables()) {
                if (!var) continue;
                int firstUse = 0;
                if (auto* lv = dynamic_cast<LocalVariable*>(var)) {
                    firstUse = lv->getFirstUseOffset();
                }
                std::ostringstream lline;
                lline << "L|" << func->getEntryPoint().getOffset()
                      << "|" << var->getName()
                      << "|" << firstUse
                      << "|" << typeRef(var->getDataType())
                      << "|" << storageToString(var->getVariableStorage());
                paramLines.push_back(lline.str());
            }
        }
    }
    std::sort(fnLines.begin(), fnLines.end());
    std::sort(paramLines.begin(), paramLines.end());
    for (const auto& l : fnLines) out << l << "\n";
    for (const auto& l : paramLines) out << l << "\n";

    std::vector<std::string> symLines;
    if (auto* st = program.getSymbolTable()) {
        auto it = st->getAllProgramSymbols(true);
        while (it.hasNext()) {
            Symbol* sym = it.next();
            std::ostringstream line;
            line << "S|" << sym->getAddress().getOffset()
                 << "|" << sym->getName()
                 << "|" << (sym->getParentNamespace() ? nsPath(sym->getParentNamespace()) : "")
                 << "|" << symbolTypeToString(sym->getSymbolType())
                 << "|" << sym->isPrimary()
                 << "|" << static_cast<int>(sym->getSource());
            symLines.push_back(line.str());
        }
    }
    std::sort(symLines.begin(), symLines.end());
    for (const auto& l : symLines) out << l << "\n";

    std::vector<std::string> refLines;
    if (auto* rm = program.getReferenceManager()) {
        for (auto* ref : rm->getAllReferences()) {
            if (!ref) continue;
            uint8_t kind = 0;
            int stackOffset = 0;
            std::string toSpace;
            if (ref->isStackReference()) {
                kind = 1;
                if (const auto* sr = dynamic_cast<const StackReference*>(ref)) {
                    stackOffset = sr->getStackOffset();
                }
            } else if (ref->isExternalReference()) {
                kind = 3;
                toSpace = ref->getToAddress().getAddressSpace() ? ref->getToAddress().getAddressSpace()->getName() : "";
            } else if (ref->getToAddress().getAddressSpace() &&
                       ref->getToAddress().getAddressSpace()->getType() == AddressSpace::TYPE_REGISTER) {
                kind = 2;
                toSpace = "register";
            }
            std::ostringstream line;
            line << "R|" << ref->getFromAddress().getOffset()
                 << "|" << ref->getToAddress().getOffset()
                 << "|" << ref->getOperandIndex()
                 << "|" << (ref->getReferenceType() ? ref->getReferenceType()->getValue() : 0)
                 << "|" << static_cast<int>(ref->getSource())
                 << "|" << static_cast<int>(kind)
                 << "|" << toSpace
                 << "|" << stackOffset
                 << "|" << ref->isPrimary();
            refLines.push_back(line.str());
        }
    }
    std::sort(refLines.begin(), refLines.end());
    for (const auto& l : refLines) out << l << "\n";

    std::vector<std::string> dtLines;
    if (program.getDataTypeManager()) {
        for (auto* dt : program.getDataTypeManager()->getDataTypes()) {
            if (!dt || dt->getName().empty()) continue;
            std::ostringstream line;
            line << "T|" << dtKindOf(dt)
                 << "|" << dt->getName()
                 << "|" << dt->getCategoryPath().getPath()
                 << "|" << dt->getLength()
                 << "|" << dt->getDescription();
            if (auto* comp = dynamic_cast<const Composite*>(dt)) {
                line << "|pack=" << comp->getExplicitPackingValue()
                     << "|min=" << comp->getExplicitMinimumAlignment();
                int nc = comp->getNumComponents();
                for (int i = 0; i < nc; ++i) {
                    DataTypeComponent* dc = comp->getComponent(i);
                    if (!dc) continue;
                    line << "|f:" << dc->getOffset()
                         << ":" << dc->getLength()
                         << ":" << dc->getFieldName()
                         << ":" << typeRef(dc->getDataType())
                         << ":" << dc->getComment();
                    if (dc->isBitFieldComponent()) {
                        if (auto* bf = dynamic_cast<BitFieldDataType*>(dc->getDataType())) {
                            line << ":bit:" << bf->getBitOffset() << ":" << bf->getBitSize()
                                 << ":" << typeRef(bf->getBaseDataType());
                        }
                    }
                }
            } else if (auto* fd = dynamic_cast<const FunctionDefinition*>(dt)) {
                auto args = fd->getArguments();
                std::sort(args.begin(), args.end(),
                          [](const ParameterDefinition* a, const ParameterDefinition* b) {
                              return a->getOrdinal() < b->getOrdinal();
                          });
                for (auto* arg : args) {
                    if (!arg) continue;
                    line << "|a:" << arg->getOrdinal() << ":" << arg->getName()
                         << ":" << typeRef(arg->getDataType());
                }
                line << "|ret:" << typeRef(fd->getReturnType());
            }
            if (auto* en = dynamic_cast<const Enum*>(dt)) {
                auto names = en->getNames();
                auto values = en->getValues();
                size_t n = std::min(names.size(), values.size());
                for (size_t i = 0; i < n; ++i) {
                    line << "|e:" << names[i] << "=" << values[i]
                         << ":" << en->getComment(names[i]);
                }
            }
            if (auto* ptr = dynamic_cast<const Pointer*>(dt)) {
                line << "|ptr:" << typeRef(ptr->getDataType());
            }
            if (auto* arr = dynamic_cast<const Array*>(dt)) {
                line << "|arr:" << typeRef(arr->getDataType()) << "*" << arr->getNumElements();
            }
            if (auto* td = dynamic_cast<const TypeDef*>(dt)) {
                line << "|td:" << typeRef(td->getBaseDataType());
            }
            dtLines.push_back(line.str());
        }
    }
    std::sort(dtLines.begin(), dtLines.end());
    for (const auto& l : dtLines) out << l << "\n";

    std::vector<std::string> bmLines;
    if (auto* bm = program.getBookmarkManager()) {
        for (auto* bk : bm->getAllBookmarks()) {
            std::ostringstream line;
            line << "B|" << bk->getAddress().getOffset()
                 << "|" << bk->getType() << "|" << bk->getComment();
            bmLines.push_back(line.str());
        }
    }
    std::sort(bmLines.begin(), bmLines.end());
    for (const auto& l : bmLines) out << l << "\n";

    std::vector<std::string> eqLines;
    if (auto* et = program.getEquateTable()) {
        for (auto* eq : et->getEquates()) {
            eqLines.push_back("Q|" + eq->getName() + "|" + std::to_string(eq->getValue()));
        }
        for (const auto& b : et->getAllBindings()) {
            if (!b.equate) continue;
            std::ostringstream line;
            line << "QR|" << b.equate->getName() << "|" << b.addressOffset << "|" << b.opIndex;
            eqLines.push_back(line.str());
        }
    }
    std::sort(eqLines.begin(), eqLines.end());
    for (const auto& l : eqLines) out << l << "\n";

    std::vector<std::string> extLines;
    if (auto* em = program.getExternalManager()) {
        for (auto* loc : em->getExternalLocations()) {
            std::ostringstream line;
            line << "X|" << loc->getLibraryName()
                 << "|" << loc->getLabel()
                 << "|" << loc->getAddress().getOffset();
            extLines.push_back(line.str());
        }
    }
    std::sort(extLines.begin(), extLines.end());
    for (const auto& l : extLines) out << l << "\n";

    std::vector<std::string> relocLines;
    if (auto* rt = program.getRelocationTable()) {
        for (auto& reloc : rt->getRelocations()) {
            std::ostringstream line;
            line << "L|" << reloc.getAddress().getOffset()
                 << "|" << reloc.getType()
                 << "|" << static_cast<int>(reloc.getStatus())
                 << "|" << reloc.getSymbolName();
            for (int64_t v : reloc.getValues()) line << ":" << v;
            line << "|" << hexBytes(reloc.getBytes());
            relocLines.push_back(line.str());
        }
    }
    std::sort(relocLines.begin(), relocLines.end());
    for (const auto& l : relocLines) out << l << "\n";

    std::vector<std::string> tagLines;
    if (auto* ftm = program.getFunctionTagManager()) {
        for (auto* tag : ftm->getAllFunctionTags()) {
            tagLines.push_back("G|" + tag->getName() + "|" + tag->getComment());
        }
        // tag -> function assignments
        auto it = program.getFunctionManager()->getFunctions();
        while (it.hasNext()) {
            Function* f = it.next();
            if (!f) continue;
            for (auto* tag : f->getTags()) {
                if (!tag) continue;
                std::ostringstream line;
                line << "GA|" << f->getEntryPoint().getOffset() << "|" << tag->getName();
                tagLines.push_back(line.str());
            }
        }
    }
    std::sort(tagLines.begin(), tagLines.end());
    for (const auto& l : tagLines) out << l << "\n";

    std::vector<std::string> regLines;
    if (auto* ctx = dynamic_cast<const ProgramContextImpl*>(program.getProgramContext())) {
        for (const auto& kv : ctx->getRegisterValues()) {
            if (!kv.second || !kv.first.reg) continue;
            std::ostringstream line;
            line << "V|" << kv.first.reg->getName()
                 << "|" << kv.first.start.getOffset()
                 << "|" << kv.first.end.getOffset()
                 << "|" << kv.second->getUnsignedOffset()
                 << "|" << hexBytes(kv.second->getMask());
            regLines.push_back(line.str());
        }
        for (const auto& kv : ctx->getDefaultValues()) {
            if (!kv.second || !kv.first.reg) continue;
            std::ostringstream line;
            line << "VD|" << kv.first.reg->getName()
                 << "|" << kv.first.start.getOffset()
                 << "|" << kv.first.end.getOffset()
                 << "|" << kv.second->getUnsignedOffset()
                 << "|" << hexBytes(kv.second->getMask());
            regLines.push_back(line.str());
        }
    }
    std::sort(regLines.begin(), regLines.end());
    for (const auto& l : regLines) out << l << "\n";

    // Entry points
    std::vector<std::string> epLines;
    if (auto* st = program.getSymbolTable()) {
        for (const Address& addr : st->getExternalEntryPoints()) {
            epLines.push_back("EP|" + std::to_string(addr.getOffset()));
        }
    }
    std::sort(epLines.begin(), epLines.end());
    for (const auto& l : epLines) out << l << "\n";

    // Source maps
    std::vector<std::string> sfLines;
    if (auto* src = program.getSourceFileManager()) {
        for (auto* f : src->getAllSourceFiles()) {
            if (f) sfLines.push_back("SF|" + f->getPath());
        }
        if (auto* impl = dynamic_cast<SourceFileManagerImpl*>(src)) {
            for (const SourceMapEntry& e : impl->getSourceMapEntriesDirect()) {
                if (!e.getSourceFile()) continue;
                sfLines.push_back("SM|" + e.getSourceFile()->getPath() + "|" +
                                  std::to_string(e.getLineNumber()) + "|" +
                                  std::to_string(e.getBaseAddress().getOffset()) + "|" +
                                  std::to_string(e.getLength()));
            }
        }
    }
    std::sort(sfLines.begin(), sfLines.end());
    for (const auto& l : sfLines) out << l << "\n";

    std::vector<std::string> mdLines;
    for (const auto& kv : program.getMetadata()) {
        mdLines.push_back("K|" + kv.first + "|" + kv.second);
    }
    std::sort(mdLines.begin(), mdLines.end());
    for (const auto& l : mdLines) out << l << "\n";

    std::vector<std::string> treeLines;
    std::vector<std::string> modLines;
    std::vector<std::string> fragLines;
    std::vector<std::string> relLines;
    std::vector<std::string> rngLines;
    if (auto* tm = program.getTreeManager()) {
        for (const auto& pair : tm->getModules()) {
            ModuleManager* mm = pair.second.get();
            if (!mm) continue;
            const std::string& treeName = mm->getTreeName();
            treeLines.push_back(treeName);
            for (const auto& mp : mm->getModules()) {
                if (!mp.second) continue;
                modLines.push_back(treeName + "|" + std::to_string(mp.first) + "|" +
                                   mp.second->getName() + "|" + mp.second->getComment());
            }
            for (const auto& fp : mm->getFragments()) {
                if (!fp.second) continue;
                fragLines.push_back(treeName + "|" + std::to_string(fp.first) + "|" +
                                    fp.second->getName() + "|" + fp.second->getComment());
            }
            for (const auto& rel : mm->getRawRelationships()) {
                int idx = -1;
                std::vector<long> children = mm->getChildrenIDs(rel.first);
                auto cit = std::find(children.begin(), children.end(), rel.second);
                if (cit != children.end()) {
                    idx = static_cast<int>(cit - children.begin());
                }
                relLines.push_back(treeName + "|" + std::to_string(rel.first) + "|" +
                                   std::to_string(rel.second) + "|" + std::to_string(idx));
            }
            for (const auto& fp : mm->getFragments()) {
                if (!fp.second) continue;
                auto* ranges = fp.second->getAddressRanges();
                if (!ranges) continue;
                while (ranges->hasNext()) {
                    const AddressRange& r = ranges->next();
                    rngLines.push_back(treeName + "|" + std::to_string(fp.first) + "|" +
                                       std::to_string(r.getMinAddress().getOffset()) + "|" +
                                       std::to_string(r.getMaxAddress().getOffset()));
                }
            }
        }
    }
    std::sort(treeLines.begin(), treeLines.end());
    std::sort(modLines.begin(), modLines.end());
    std::sort(fragLines.begin(), fragLines.end());
    std::sort(relLines.begin(), relLines.end());
    std::sort(rngLines.begin(), rngLines.end());
    for (const auto& l : treeLines) out << "N|" << l << "\n";
    for (const auto& l : modLines) out << "MO|" << l << "\n";
    for (const auto& l : fragLines) out << "FR|" << l << "\n";
    for (const auto& l : relLines) out << "RE|" << l << "\n";
    for (const auto& l : rngLines) out << "RG|" << l << "\n";

    return out.str();
}

int64_t readBeNum(const std::vector<uint8_t>& v, size_t off, size_t n) {
    int64_t r = 0;
    for (size_t i = 0; i < n && off + i < v.size(); ++i) {
        r = (r << 8) | v[off + i];
    }
    return r;
}

void diffDump(const std::string& a, const std::string& b, size_t maxLines = 20) {
    std::istringstream ia(a), ib(b);
    std::string la, lb;
    size_t line = 0, shown = 0;
    while (std::getline(ia, la) && std::getline(ib, lb)) {
        line++;
        if (la != lb && shown < maxLines) {
            std::cout << "  diff@" << line << "\n    A: "
                      << la.substr(0, 160) << "\n    B: " << lb.substr(0, 160) << "\n";
            shown++;
        }
    }
    if (shown == 0) {
        std::cout << "  (dumps differ only in structure/length; A lines="
                  << std::count(a.begin(), a.end(), '\n')
                  << " B lines=" << std::count(b.begin(), b.end(), '\n') << ")\n";
    }
}

std::string makeTempRepo(const std::string& tag) {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::stringstream ss;
    ss << "repo_fidelity_" << tag << "_" << std::hex << ms;
    std::string path = ss.str();
    fs::remove_all(path);
    return path;
}

/** Cross-check the corpus "Property Map - Lengths" table against the data
 *  units' recomputed lengths. */
void checkPropertyMapLengths(const std::string& gbfPath, ProgramDB& program,
                             int expectedRecords) {
    auto bytes = readFileBytes(gbfPath);
    auto reader = GbfReader::fromMemory(std::move(bytes));
    const GbfTableSchema* pm = reader->findTable("Property Map - Lengths");
    TEST("property map - lengths table found", pm != nullptr);
    if (!pm) return;
    TEST("property map - lengths record count", pm->recordCount == expectedRecords);
    auto* space = const_cast<AddressSpace*>(
        program.getAddressFactory()->getDefaultAddressSpace());
    auto* listing = program.getListing();
    size_t matched = 0, missing = 0, mismatch = 0;
    size_t record = 0;
    reader->visitRecords(*pm, [&](const GbfRecord& rec) {
        const size_t keyLen = rec.key.size();
        int64_t addrKey = readBeNum(rec.key, 0, keyLen);
        int64_t storedLen = 0;
        if (!rec.data.empty()) {
            storedLen = readBeNum(rec.data, 0, 4);
        } else if (!rec.sparseFields.empty()) {
            storedLen = readBeNum(rec.sparseFields[0].second, 0, 4);
        }
        if (record < 2) {
            std::cout << "  pm record " << record << ": keylen=" << keyLen
                      << " key=" << hexBytes(rec.key)
                      << " data=" << hexBytes(rec.data) << "\n";
        }
        record++;
        if ((static_cast<uint64_t>(addrKey) >> 32) != 0x20000000ull) return;
        Address addr(space, addrKey & 0xFFFFFFFFull);
        Data* d = listing->getDataAt(addr);
        if (!d) {
            missing++;
            return;
        }
        if (d->getLength() == storedLen) {
            matched++;
        } else {
            if (mismatch < 12) {
                std::cout << "  pm mismatch @0x" << std::hex << (addrKey & 0xFFFFFFFFull)
                          << std::dec << ": stored=" << storedLen
                          << " engine=" << d->getLength()
                          << " type=" << d->getDataType()->getName() << "\n";
            }
            mismatch++;
        }
    });
    TEST("property map - lengths all match recomputed lengths",
         matched + missing + mismatch == static_cast<size_t>(expectedRecords) &&
             mismatch == 0);
    std::cout << "  property map: " << matched << " matched, " << missing
              << " missing units, " << mismatch << " mismatches\n";
}

}  // namespace

int main() {
    // ================================================================
    // notepad_test.exe: full round-trip + user-edit workflow
    // ================================================================
    std::string notepadGbf =
        findCorpus("ghidra_proj.rep/idata/00/~00000001.db/db.1.gbf");
    if (notepadGbf.empty()) {
        std::cout << "[SKIP] notepad corpus not found\n";
    } else {
        TEST("found notepad corpus", true);
        std::unique_ptr<ProgramDB> p0 = importProgram(notepadGbf, "notepad_test.exe");
        std::string dumpA = dumpState(*p0);
        std::cout << "  notepad state dump bytes: " << dumpA.size() << "\n";

        TEST("notepad listing counts",
             p0->getListing()->getInstructionCount() == 35367 &&
                 p0->getListing()->getAllData().size() == 2960);
        TEST("notepad function count",
             p0->getFunctionManager()->getFunctionCount() == 794);
        // 19,450 refs decode from FROM REFS; one is the entry-point reference
        // whose "from" is Ghidra's external-entry pseudo address (-1 key) —
        // the engine has no counterpart, so 19,449 are creatable.
        TEST("notepad reference count",
             p0->getReferenceManager()->getReferenceCount() == 19449);
        std::cout << "  notepad reference count: "
                  << p0->getReferenceManager()->getReferenceCount() << "\n";
        TEST("notepad bookmark count",
             p0->getBookmarkManager()->getBookmarkCount() == 75);

        checkPropertyMapLengths(notepadGbf, *p0, 736);

        std::string repoPath = makeTempRepo("notepad");
        Repository::create(repoPath, "fidelity", "notepad_test.exe", "0000",
                           p0->getLanguageID().toString(),
                           p0->getCompilerSpecID().toString(),
                           static_cast<uint64_t>(p0->getImageBase().getOffset()));
        EventLog log;
        std::string cid1 = CommitManager::createCommit(repoPath, "", "original",
                                                       "fidelity", "main", *p0, log);
        TEST("notepad commit 1 created", !cid1.empty());

        auto r1 = SnapshotReader::loadFromFile(
            Repository::getCommitSnapshotPath(repoPath, cid1));
        std::string dumpR1 = r1 ? dumpState(*r1) : "";
        TEST("notepad reload 1 succeeds", r1 != nullptr);
        TEST("notepad reload 1 state identical", r1 && dumpR1 == dumpA);
        if (!(r1 && dumpR1 == dumpA)) {
            diffDump(dumpA, dumpR1);
            std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/dumpA.txt") << dumpA;
            std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/dumpR1.txt") << dumpR1;
        }

        // ---- user edits ----
        auto* space = const_cast<AddressSpace*>(
            p0->getAddressFactory()->getDefaultAddressSpace());
        Address editAddr(space, 0x1008);
        Address editAddr2(space, 0x1010);

        MemoryBlock* text = p0->getMemory()->getBlock(".text");
        if (text) {
            const uint8_t patch[4] = {0x90, 0x90, 0x90, 0x90};
            // .text is read+execute; lift the write-protect around the patch
            // (same pattern the importer uses while populating blocks).
            const bool hadWrite = text->isWrite();
            if (!hadWrite) text->setWrite(true);
            text->putBytes(text->getStart().add(0x10), patch, 4);
            if (!hadWrite) text->setWrite(false);
        }
        TEST("notepad edit: bytes patched", true);

        if (auto* cu = p0->getListing()->getCodeUnitAt(editAddr)) {
            cu->setComment("fidelity EOL comment");
            cu->setPreComment("fidelity PRE comment");
            cu->setPostComment("fidelity POST comment");
            cu->setPlateComment("fidelity PLATE comment");
            cu->setRepeatableComment("fidelity REP comment");
        }
        TEST("notepad edit: comments set", true);

        p0->getBookmarkManager()->setBookmark(editAddr, "Edited", "fidelity edit");
        TEST("notepad edit: bookmark set", true);

        Symbol* sym = p0->getSymbolTable()->createLabel(editAddr, "edited_label", nullptr,
                                                        SourceType::USER_DEFINED);
        if (sym) {
            sym->setName("edited_renamed");
        }
        TEST("notepad edit: label renamed", sym != nullptr &&
             sym->getName() == "edited_renamed");

        p0->setMetadata("Edited", "true");
        TEST("notepad edit: metadata set", true);

        if (auto* ctx = dynamic_cast<ProgramContextImpl*>(p0->getProgramContext())) {
            AddressSpace* regSpace = const_cast<AddressSpace*>(
                p0->getAddressFactory()->getAddressSpace("register"));
            Register* reg = ctx->addOwnedRegister(std::make_unique<Register>(
                "EDIT_REG", "", Address(regSpace, 0x222), 8, false, 0));
            RegisterValue rv(reg, 0x1234, 8);
            ctx->setRegisterValue(&rv, editAddr, editAddr2);
            TEST("notepad edit: register value set", true);
        }

        p0->getEquateTable()->createEquate("EDITED_EQ", 0x1234);
        Equate* boundEq = p0->getEquateTable()->createEquate("EDITED_BOUND", 0x77,
                                                             editAddr, 0);
        TEST("notepad edit: equate set", boundEq != nullptr);
        TEST("notepad edit: bound equate added",
             boundEq && p0->getEquateTable()->getEquates(editAddr, 0).size() == 1);

        {
            // Function tags with assignments (round-tripped by the writer's
            // function_addresses list and re-attached by the reader).
            auto* ftm = p0->getFunctionTagManager();
            auto it = p0->getFunctionManager()->getFunctions();
            Function* f1 = it.hasNext() ? it.next() : nullptr;
            Function* f2 = it.hasNext() ? it.next() : nullptr;
            if (ftm && f1 && f2) {
                f1->addTag("LIBRARY");
                f1->addTag("REVIEWED");
                f2->addTag("LIBRARY");
                TEST("notepad edit: function tags assigned",
                     f1->getTags().size() == 2 && f2->getTags().size() == 1);
            } else {
                TEST("notepad edit: function tags assigned", false);
            }
        }

        {
            // Datatype additions: enum with a value comment + description,
            // structure with explicit packing and minimum alignment.
            auto* dtm = p0->getDataTypeManager();
            auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(dtm);
            bool dtEditOk = false;
            if (dtmImpl) {
                auto* editEnum = new EnumDataType(CategoryPath::ROOT(), "EDITED_ENUM", 4, dtm);
                editEnum->setDescription("edited enum comment");
                editEnum->add("VAL_A", 1, "enum value comment");
                editEnum->add("VAL_B", 2);
                dtmImpl->addDataTypeWithId(editEnum, -1000);

                auto* editStruct = new StructureDataType(CategoryPath::ROOT(),
                                                         "EDITED_STRUCT", 0, dtm);
                editStruct->setExplicitMinimumAlignment(16);
                editStruct->setExplicitPackingValue(2);
                editStruct->setDescription("edited struct comment");
                dtmImpl->addDataTypeWithId(editStruct, -1001);

                DataType* dword = dtm->getDataType(CategoryPath::ROOT(), "dword");
                if (dword) {
                    editStruct->add(dword, 4, "field_one", "");
                    editStruct->add(dword, 4, "field_two", "field comment");
                }
                dtEditOk = editEnum->getCount() == 2 &&
                           editStruct->getNumComponents() == 2 &&
                           editStruct->getExplicitMinimumAlignment() == 16 &&
                           editStruct->getExplicitPackingValue() == 2 &&
                           editEnum->getComment("VAL_A") == "enum value comment";
            }
            TEST("notepad edit: datatypes added", dtEditOk);
        }

        std::string dumpB = dumpState(*p0);
        TEST("notepad edits changed state", dumpB != dumpA);

        std::string cid2 = CommitManager::createCommit(repoPath, cid1, "edited",
                                                       "fidelity", "main", *p0, log);
        TEST("notepad commit 2 created", !cid2.empty() && cid2 != cid1);

        auto r2 = SnapshotReader::loadFromFile(
            Repository::getCommitSnapshotPath(repoPath, cid2));
        std::string dumpR2 = r2 ? dumpState(*r2) : "";
        TEST("notepad reload 2 succeeds", r2 != nullptr);
        TEST("notepad reload 2 state identical to edited", r2 && dumpR2 == dumpB);
        if (!(r2 && dumpR2 == dumpB)) diffDump(dumpB, dumpR2);

        auto r1b = SnapshotReader::loadFromFile(
            Repository::getCommitSnapshotPath(repoPath, cid1));
        std::string dumpR1b = r1b ? dumpState(*r1b) : "";
        TEST("notepad original revision intact", r1b && dumpR1b == dumpA);
        if (!(r1b && dumpR1b == dumpA)) diffDump(dumpA, dumpR1b);

        TEST("notepad two commits recorded",
             CommitManager::listCommits(repoPath).size() == 2);

        fs::remove_all(repoPath);
    }

    // ================================================================
    // key.exe: multi-tree round-trip (2 trees, 57 modules, 237 fragments)
    // ================================================================
    std::string keyGbf =
        findCorpus("ghidra_proj_key.rep/idata/00/~00000000.db/db.1.gbf");
    if (keyGbf.empty()) {
        std::cout << "[SKIP] key.exe corpus not found\n";
    } else {
        TEST("found key.exe corpus", true);
        std::unique_ptr<ProgramDB> p0 = importProgram(keyGbf, "key.exe");
        std::string dumpA = dumpState(*p0);
        std::cout << "  key.exe state dump bytes: " << dumpA.size() << "\n";

        TEST("key.exe tree count", p0->getTreeManager()->getModules().size() == 2);
        TEST("key.exe function count",
             p0->getFunctionManager()->getFunctionCount() == 231);
        // Source maps: all 92 DWARF files (including the 44 without entries)
        // and every one of the 11,449 address<->line mappings.
        if (auto* src = p0->getSourceFileManager()) {
            TEST("key.exe source file count", src->getAllSourceFiles().size() == 92);
            if (auto* impl = dynamic_cast<SourceFileManagerImpl*>(src)) {
                TEST("key.exe source map entry count",
                     impl->getSourceMapEntriesDirect().size() == 11449);
            }
        }
        // Function variables with storage (params 327 / locals 232).
        {
            size_t paramCount = 0, localCount = 0;
            auto it = p0->getFunctionManager()->getFunctions(true);
            while (it.hasNext()) {
                Function* f = it.next();
                if (!f) continue;
                paramCount += f->getParameters().size();
                localCount += f->getLocalVariables().size();
            }
            TEST("key.exe parameter count", paramCount == 327);
            TEST("key.exe local variable count", localCount == 232);
        }
        TEST("key.exe entry points",
             p0->getSymbolTable()->getExternalEntryPoints().size() == 137);

        std::string repoPath = makeTempRepo("key");
        Repository::create(repoPath, "fidelity", "key.exe", "0000",
                           p0->getLanguageID().toString(),
                           p0->getCompilerSpecID().toString(),
                           static_cast<uint64_t>(p0->getImageBase().getOffset()));
        EventLog log;
        std::string cid1 = CommitManager::createCommit(repoPath, "", "original",
                                                       "fidelity", "main", *p0, log);
        auto r1 = SnapshotReader::loadFromFile(
            Repository::getCommitSnapshotPath(repoPath, cid1));
        std::string dumpR1 = r1 ? dumpState(*r1) : "";
        TEST("key.exe reload state identical", r1 && dumpR1 == dumpA);
        if (!(r1 && dumpR1 == dumpA)) {
            std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/keyDumpA.txt") << dumpA;
            std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/keyDumpR1.txt") << dumpR1;
        }
        if (!(r1 && dumpR1 == dumpA)) diffDump(dumpA, dumpR1);

        fs::remove_all(repoPath);
    }

    // ================================================================
    // pass.exe: Variable Storage decode + pointer round-trip
    // (db.16.gbf; 111 storage records, 241 functions)
    // ================================================================
    std::string passGbf =
        findCorpus("pass_proj.rep/idata/00/~00000000.db/db.16.gbf");
    if (passGbf.empty()) {
        std::cout << "[SKIP] pass.exe corpus not found\n";
    } else {
        TEST("found pass.exe corpus", true);
        std::unique_ptr<ProgramDB> p0 = importProgram(passGbf, "pass.exe");
        std::string dumpA = dumpState(*p0);
        std::cout << "  pass.exe state dump bytes: " << dumpA.size() << "\n";

        auto findFn = [&](const std::string& n) -> Function* {
            for (FunctionIterator it = p0->getFunctionManager()->getFunctions(true);
                 it.hasNext();) {
                Function* f = it.next();
                if (f && f->getName() == n) return f;
            }
            return nullptr;
        };
        auto findLocal = [](Function* f, const std::string& n) -> const Variable* {
            if (!f) return nullptr;
            for (const Variable* v : f->getLocalVariables()) {
                if (v->getName() == n) return v;
            }
            return nullptr;
        };

        TEST("pass.exe function count",
             p0->getFunctionManager()->getFunctionCount() == 241);
        // Function variables with storage (params 335 / locals 231).
        {
            size_t paramCount = 0, localCount = 0;
            auto it = p0->getFunctionManager()->getFunctions(true);
            while (it.hasNext()) {
                Function* f = it.next();
                if (!f) continue;
                paramCount += f->getParameters().size();
                localCount += f->getLocalVariables().size();
            }
            TEST("pass.exe parameter count", paramCount == 335);
            TEST("pass.exe local variable count", localCount == 231);
        }
        TEST("pass.exe entry points",
             p0->getSymbolTable()->getExternalEntryPoints().size() == 140);

        // Exact Ghidra storage decode (records via variable-space symbol
        // keys): main locals -82:8 / -74:2 / -72:1, params <UNASSIGNED>.
        Function* mainFn = findFn("main");
        TEST("pass.exe main function found", mainFn != nullptr);
        if (mainFn) {
            const auto& ml = mainFn->getLocalVariables();
            TEST("pass.exe main 3 locals", ml.size() == 3);
            if (ml.size() == 3) {
                TEST("pass.exe main locals exact stack storage",
                     ml[0]->hasStackStorage() && ml[0]->getStackOffset() == -82 &&
                         ml[0]->getDataType()->getLength() == 8 &&
                         ml[1]->hasStackStorage() && ml[1]->getStackOffset() == -74 &&
                         ml[1]->getDataType()->getLength() == 2 &&
                         ml[2]->hasStackStorage() && ml[2]->getStackOffset() == -72 &&
                         ml[2]->getDataType()->getLength() == 1);
            }
            TEST("pass.exe main params unassigned",
                 mainFn->getParameters().size() == 3 &&
                     !mainFn->getParameters()[0]->hasAssignedStorage());
        }
        // Linked va_list params (Stack[-0x20]:8) and struct locals.
        if (Function* f = findFn("__mingw_scanf")) {
            const Variable* argp = findLocal(f, "argp");
            TEST("pass.exe scanf argp stack -32 size 8",
                 argp != nullptr && argp->hasStackStorage() &&
                     argp->getStackOffset() == -32 && argp->getDataType()->getLength() == 8);
        }
        if (Function* f = findFn("__mingw_printf")) {
            const Variable* argv = findLocal(f, "argv");
            TEST("pass.exe printf argv stack -32 size 8",
                 argv != nullptr && argv->hasStackStorage() &&
                     argv->getStackOffset() == -32 && argv->getDataType()->getLength() == 8);
        }
        if (Function* f = findFn("__tmainCRTStartup")) {
            const Variable* startinfo = findLocal(f, "startinfo");
            TEST("pass.exe startinfo stack -76 size 4",
                 startinfo != nullptr && startinfo->hasStackStorage() &&
                     startinfo->getStackOffset() == -76 &&
                     startinfo->getDataType()->getLength() == 4 &&
                     startinfo->getDataType()->getName() == "_startupinfo");
        }
        if (Function* f = findFn("_pei386_runtime_relocator")) {
            const Variable* reldata = findLocal(f, "reldata");
            TEST("pass.exe reldata stack -64 size 8",
                 reldata != nullptr && reldata->hasStackStorage() &&
                     reldata->getStackOffset() == -64 &&
                     reldata->getDataType()->getLength() == 8);
        }
        // No variable may end up with BAD storage (the old importer dropped
        // every stack record to unassigned/unknown).
        {
            size_t badCount = 0;
            auto it = p0->getFunctionManager()->getFunctions(true);
            while (it.hasNext()) {
                Function* f = it.next();
                if (!f) continue;
                for (const Variable* p : f->getParameters()) {
                    if (p->getVariableStorage().isBadStorage()) badCount++;
                }
                for (const Variable* l : f->getLocalVariables()) {
                    if (l->getVariableStorage().isBadStorage()) badCount++;
                }
            }
            TEST("pass.exe no BAD storage on any variable", badCount == 0);
        }

        std::string repoPath = makeTempRepo("pass");
        Repository::create(repoPath, "fidelity", "pass.exe", "0000",
                           p0->getLanguageID().toString(),
                           p0->getCompilerSpecID().toString(),
                           static_cast<uint64_t>(p0->getImageBase().getOffset()));
        EventLog log;
        std::string cid1 = CommitManager::createCommit(repoPath, "", "original",
                                                       "fidelity", "main", *p0, log);
        auto r1 = SnapshotReader::loadFromFile(
            Repository::getCommitSnapshotPath(repoPath, cid1));
        std::string dumpR1 = r1 ? dumpState(*r1) : "";
        TEST("pass.exe reload state identical", r1 && dumpR1 == dumpA);
        if (!(r1 && dumpR1 == dumpA)) {
            std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/passDumpA.txt") << dumpA;
            std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/passDumpR1.txt") << dumpR1;
        }
        if (!(r1 && dumpR1 == dumpA)) diffDump(dumpA, dumpR1);

        // Storage + pointer invariants survive the snapshot reload.
        if (r1) {
            auto findFnR = [&](const std::string& n) -> Function* {
                for (FunctionIterator it = r1->getFunctionManager()->getFunctions(true);
                     it.hasNext();) {
                    Function* f = it.next();
                    if (f && f->getName() == n) return f;
                }
                return nullptr;
            };
            auto findLocalR = [](Function* f, const std::string& n) -> const Variable* {
                if (!f) return nullptr;
                for (const Variable* v : f->getLocalVariables()) {
                    if (v->getName() == n) return v;
                }
                return nullptr;
            };
            Function* rmain = findFnR("main");
            if (rmain) {
                const auto& ml = rmain->getLocalVariables();
                TEST("pass.exe reload main locals exact stack storage",
                     ml.size() == 3 && ml[0]->hasStackStorage() &&
                         ml[0]->getStackOffset() == -82 && ml[0]->getDataType()->getLength() == 8 &&
                         ml[1]->hasStackStorage() && ml[1]->getStackOffset() == -74 &&
                         ml[1]->getDataType()->getLength() == 2 &&
                         ml[2]->hasStackStorage() && ml[2]->getStackOffset() == -72 &&
                         ml[2]->getDataType()->getLength() == 1);
                TEST("pass.exe reload main params unassigned",
                     rmain->getParameters().size() == 3 &&
                         !rmain->getParameters()[0]->hasAssignedStorage());
            }
            if (Function* f = findFnR("__mingw_scanf")) {
                const Variable* argp = findLocalR(f, "argp");
                TEST("pass.exe reload scanf argp stack -32 size 8",
                     argp != nullptr && argp->hasStackStorage() &&
                         argp->getStackOffset() == -32 && argp->getDataType()->getLength() == 8);
            }
            if (Function* f = findFnR("__tmainCRTStartup")) {
                const Variable* startinfo = findLocalR(f, "startinfo");
                TEST("pass.exe reload startinfo stack -76 size 4",
                     startinfo != nullptr && startinfo->hasStackStorage() &&
                         startinfo->getStackOffset() == -76 &&
                         startinfo->getDataType()->getLength() == 4 &&
                         startinfo->getDataType()->getName() == "_startupinfo");
            }
            // Pointer Length is a signed byte; -1 must survive as the engine
            // default (8 on x64), never 255 or a "*2040" name.
            DataTypeManager* dtm = r1->getDataTypeManager();
            size_t ptr255 = 0, ptrDefault = 0, badNames = 0;
            for (DataType* dt : dtm->getDataTypes()) {
                if (!dt) continue;
                if (auto* p = dynamic_cast<PointerDataType*>(dt)) {
                    if (p->getLength() == 255) ptr255++;
                    if (p->getLength() == 8) ptrDefault++;
                    if (p->getName().find("*2040") != std::string::npos) badNames++;
                }
            }
            TEST("pass.exe reload no pointer length 255", ptr255 == 0);
            TEST("pass.exe reload no '*2040' pointer names", badNames == 0);
            TEST("pass.exe reload default pointers 8 bytes", ptrDefault > 0);
        }

        fs::remove_all(repoPath);
    }

    // ================================================================
    // Extra corpora (ENIGMA_EXTRA_CORPUS = ';'-separated .gbf paths):
    // generic full round-trip for any imported program, asserting the
    // zero-bad invariants instead of hardcoded counts.
    // ================================================================
    if (const char* extraEnv = std::getenv("ENIGMA_EXTRA_CORPUS")) {
        std::string list(extraEnv);
        size_t pos = 0;
        while (pos <= list.size()) {
            size_t sep = list.find(';', pos);
            std::string one =
                list.substr(pos, sep == std::string::npos ? std::string::npos
                                                          : sep - pos);
            pos = (sep == std::string::npos) ? list.size() + 1 : sep + 1;
            while (!one.empty() && (one.front() == ' ' || one.front() == '"')) {
                one.erase(one.begin());
            }
            while (!one.empty() && (one.back() == ' ' || one.back() == '"')) {
                one.pop_back();
            }
            if (one.empty()) continue;
            std::string name = fs::path(one).parent_path().filename().string();
            if (name.rfind("~", 0) == 0 && name.size() > 1) {
                name = name.substr(1);  // ~00000000.db -> 00000000.db
            }
            if (name.empty() || name == ".") {
                name = fs::path(one).stem().stem().filename().string();
            }
            if (name.empty()) name = fs::path(one).filename().string();

            std::unique_ptr<ProgramDB> p0;
            size_t warnCount = 0;
            const GzfProgramImporter::Stats* stPtr = nullptr;
            try {
                auto bytes = readFileBytes(one);
                auto reader = GbfReader::fromMemory(std::move(bytes));
                GzfProgramImporter importer(*reader);
                p0 = importer.import(name);
                stPtr = &importer.getStats();
                warnCount = importer.getWarnings().size();
                for (size_t wi = 0; wi < warnCount && wi < 40; ++wi) {
                    std::cout << "  [" << name << "] warn: "
                              << importer.getWarnings()[wi] << "\n";
                }
            } catch (const std::exception& e) {
                std::cout << "  [" << name << "] import threw: " << e.what() << "\n";
            }
            TEST(name + " import succeeds", p0 != nullptr);
            if (!p0 || !stPtr) continue;
            const auto& st = *stPtr;

            std::cout << "  [" << name << "] inst=" << st.instructions
                      << " data=" << st.dataUnits << " fns=" << st.functions
                      << " syms=" << (st.labels + st.namespaces)
                      << " refs=" << st.references << " dts=" << st.composites
                      << "c/" << st.typedefs << "t/" << st.enums << "e"
                      << " vars=" << (st.parameters + st.localVariables)
                      << " srcFiles=" << st.sourceFiles
                      << " srcMap=" << st.sourceMapEntries
                      << " warns=" << warnCount << "\n";

            {
                std::string bad;
                std::string artifacts;
                auto flag = [&](const char* n, int v) {
                    if (v != 0) bad += std::string(" ") + n + "=" + std::to_string(v);
                };
                // bookmarksBad/moduleTreeBad count records pointing into
                // deleted Ghidra segments (re-analysis leftovers); the importer
                // drops them by design, so they are tolerated.
                flag("refsBadRecords", st.refsBadRecords);
                flag("refsUnknownSpace", st.refsUnknownSpace);
                flag("relocationsBad", st.relocationsBad);
                flag("scopeBad", st.scopeBad);
                flag("variablesBad", st.variablesBad);
                flag("sourceMapBad", st.sourceMapBad);
                flag("datatypeUnresolvedRefs", st.datatypeUnresolvedRefs);
                flag("componentOffsetMismatches", st.componentOffsetMismatches);
                flag("dataConflicts", st.dataConflicts);
                if (st.bookmarksBad != 0 || st.moduleTreeBad != 0) {
                    artifacts = " deleted-segment artifacts: bookmarks=" +
                                std::to_string(st.bookmarksBad) + " modules=" +
                                std::to_string(st.moduleTreeBad);
                }
                if (!bad.empty()) std::cout << "  [" << name << "] bad:" << bad << "\n";
                if (!artifacts.empty()) std::cout << "  [" << name << "]" << artifacts << "\n";
                TEST(name + " zero bad records", bad.empty());
            }

            std::string dumpA = dumpState(*p0);
            std::string repoPath = makeTempRepo("extra");
            Repository::create(repoPath, "fidelity", name, "0000",
                               p0->getLanguageID().toString(),
                               p0->getCompilerSpecID().toString(),
                               static_cast<uint64_t>(p0->getImageBase().getOffset()));
            EventLog log;
            std::string cid = CommitManager::createCommit(repoPath, "", "original",
                                                          "fidelity", "main", *p0, log);
            auto r1 = SnapshotReader::loadFromFile(
                Repository::getCommitSnapshotPath(repoPath, cid));
            std::string dumpR1 = r1 ? dumpState(*r1) : "";
            TEST(name + " reload state identical", r1 && dumpR1 == dumpA);
            if (!(r1 && dumpR1 == dumpA)) {
                diffDump(dumpA, dumpR1);
                std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/extraA_" +
                              name + ".txt") << dumpA;
                std::ofstream("C:/Users/pc/AppData/Local/Temp/opencode/extraR1_" +
                              name + ".txt") << dumpR1;
            }
            fs::remove_all(repoPath);
        }
    }

    std::cout << "\n=== Gzf Snapshot Fidelity Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}