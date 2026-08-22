#include <ghidra/DecompInterface.h>
#include <ghidra/Memory.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/LanguageID.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AnalysisBridge.h>
#include <ghidra/TypeDatabase.h>

#include <libdecomp.hh>
#include <sleigh_arch.hh>
#include <raw_arch.hh>
#include <loadimage.hh>
#include <printc.hh>
#include <funcdata.hh>
#include <fspec.hh>

#include <translate.hh>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <cctype>
#include <cstring>
#include <mutex>
#include <sstream>
#include <set>

namespace ghidra {

static std::mutex s_initMutex;
static bool s_libraryInitialized = false;

static std::string stripMarkup(const std::string& xml) {
    std::string s;
    s.reserve(xml.size());
    for (size_t i = 0; i < xml.size();) {
        if (xml[i] == '<') {
            size_t end = xml.find('>', i);
            if (end == std::string::npos) break;
            i = end + 1;
        } else {
            s += xml[i++];
        }
    }
    return s;
}

static bool isKeywordPreceding(const std::string& raw, size_t i) {
    if (i == 0) return false;
    size_t start = i;
    while (start > 0 && (std::isalnum(raw[start-1]) || raw[start-1] == '_')) start--;
    if (start == i) return false;
    size_t len = i - start;
    if (len == 2 && raw[start] == 'i' && raw[start+1] == 'f') return true;
    if (len == 3 && raw.compare(start, 3, "for") == 0) return true;
    if (len == 4 && raw.compare(start, 4, "case") == 0) return true;
    if (len == 2 && raw[start] == 'd' && raw[start+1] == 'o') return true;
    if (len == 5) {
        if (raw.compare(start, 5, "while") == 0) return true;
        if (raw.compare(start, 5, "switch") == 0) return true;
        if (raw.compare(start, 5, "sizeof") == 0) return true;
    }
    if (len == 6 && raw.compare(start, 6, "return") == 0) return true;
    return false;
}

static std::string resolveStringRefsInMarkup(const std::string& markup,
                                             ghidra::Memory* mem,
                                             ghidra::AddressSpace* space,
                                             uint64_t baseAddr) {
    std::string s = markup;
    // Match patterns like (char *)0xHEX — common string pointer args
    // Also: (char const*)0xHEX, (const char *)0xHEX, (char const *)0xHEX
    const char* patterns[] = {
        "(char *)0x",
        "(char const*)0x",
        "(const char *)0x",
        "(char const *)0x",
    };
    for (const char* prefix : patterns) {
        size_t plen = std::strlen(prefix);
        for (size_t pos = 0; (pos = s.find(prefix, pos)) != std::string::npos; ) {
            size_t start = pos + plen;
            size_t end = start;
            while (end < s.size() && std::isxdigit(static_cast<unsigned char>(s[end])))
                ++end;
            if (end == start) { pos = end; continue; }
            std::string hexStr = s.substr(start, end - start);
            uint64_t addr = std::stoull(hexStr, nullptr, 16);
            if (addr < baseAddr) { pos = end; continue; }
            uint64_t delta = addr - baseAddr;
            // Read null-terminated string, limit to 256 chars
            std::string strContent;
            bool printable = true;
            for (uint64_t i = delta; i < delta + 256; ++i) {
                uint8_t c = 0;
                ghidra::Address readAddr(space, static_cast<int64_t>(i));
                int n = 0;
                try { n = mem->getBytes(readAddr, &c, 1); } catch (...) { break; }
                if (n < 1 || c == 0) break;
                if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') { printable = false; break; }
                strContent += static_cast<char>(c);
            }
            if (!printable || strContent.empty()) { pos = end; continue; }
            // Build C string literal with escaping
            std::string quoted = "\"";
            for (char c : strContent) {
                switch (c) {
                case '\n': quoted += "\\n"; break;
                case '\r': quoted += "\\r"; break;
                case '\t': quoted += "\\t"; break;
                case '\\': quoted += "\\\\"; break;
                case '"':  quoted += "\\\""; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8]; std::snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c);
                        quoted += buf;
                    } else {
                        quoted += c;
                    }
                }
            }
            quoted += '"';
            s.replace(pos, end - pos, quoted);
            pos = pos + quoted.size();
        }
    }
    return s;
}

static std::string cleanCOutput(const std::string& raw) {
    std::string s;
    s.reserve(raw.size());
    size_t i = 0;
    while (i < raw.size()) {
        if (raw[i] == '{' && i + 2 < raw.size() && raw[i+1] == '\n' && raw[i+2] == '\n') { s += "{\n"; i += 3; }
        else if (i + 5 < raw.size() && raw.compare(i, 6, "(void)") == 0) { s += "()"; i += 6; }
        else if (i + 7 < raw.size() && raw.compare(i, 8, "xunknown") == 0) { s += "undefined"; i += 8; }
        else if (raw[i] == ' ' && i + 1 < raw.size() && raw[i+1] == '(' &&
                 i > 0 && (std::isalnum(raw[i-1]) || raw[i-1] == '_' || raw[i-1] == ')') &&
                 !isKeywordPreceding(raw, i)) {
            s += '('; i += 2;
        }
        else { s += raw[i++]; }
    }
    return s;
}

static std::string findSleighDir() {
    if (const char* envPath = std::getenv("ENIGMA_SLEIGH_DIR")) {
        if (*envPath && std::filesystem::exists(envPath))
            return envPath;
    }
#ifndef ENIGMA_SLEIGH_DIR
#define ENIGMA_SLEIGH_DIR ""
#endif
    std::string compilePath = ENIGMA_SLEIGH_DIR;
    if (!compilePath.empty() && std::filesystem::exists(compilePath))
        return compilePath;
    auto cwd = std::filesystem::current_path() / "sleigh";
    if (std::filesystem::is_directory(cwd))
        return cwd.string();
    return {};
}

static bool hasLdefs(const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return false;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!ec && entry.is_regular_file(ec) && entry.path().extension() == ".ldefs")
            return true;
    }
    return false;
}

static std::string registerSleighPaths() {
    std::string root = findSleighDir();
    if (root.empty()) return {};
    std::filesystem::path rootPath(root);
    if (hasLdefs(rootPath))
        ghidra_decompiler::SleighArchitecture::scanForSleighDirectories(root);
    for (const auto& entry : std::filesystem::directory_iterator(rootPath)) {
        std::error_code ec;
        if (entry.is_directory(ec) && hasLdefs(entry.path()))
            ghidra_decompiler::SleighArchitecture::scanForSleighDirectories(entry.path().string());
    }
    return root;
}

class LoadImageFromProgram : public ghidra_decompiler::LoadImage {
    Memory* memory_;
    ghidra::AddressSpace* ghidraSpace_;
public:
    LoadImageFromProgram(const std::string& fname, Memory* mem, ghidra::AddressSpace* space)
        : ghidra_decompiler::LoadImage(fname), memory_(mem), ghidraSpace_(space) {}

    void loadFill(ghidra_decompiler::uint1* ptr, ghidra_decompiler::int4 size,
                  const ghidra_decompiler::Address& addr) override {
        ghidra::Address gAddr(ghidraSpace_, static_cast<int64_t>(addr.getOffset()));
        int nread = 0;
        if (memory_) {
            try {
                nread = memory_->getBytes(gAddr, ptr, size);
            } catch (...) {
                nread = 0;
            }
        }
        if (nread < size) {
            if (nread == 0) {
                static int warnCount = 0;
                if (++warnCount <= 3)
                    std::cerr << "[WARN] LoadImageFromProgram: zero-filling " << size
                              << " bytes at 0x" << std::hex << addr.getOffset()
                              << std::dec << " (unmapped memory)" << std::endl;
            }
            std::memset(ptr + nread, 0, size - nread);
        }
    }

    std::string getArchType() const override { return "raw"; }
    void adjustVma(long) override {}
};

class ProgramArch : public ghidra_decompiler::RawBinaryArchitecture {
    ghidra_decompiler::LoadImage* customLoader_;
public:
    ProgramArch(const std::string& fname, const std::string& targ,
                std::ostream* estream, ghidra_decompiler::LoadImage* loader)
        : ghidra_decompiler::RawBinaryArchitecture(fname, targ, estream),
          customLoader_(loader) {}

    void buildLoader(ghidra_decompiler::DocumentStorage& store) override {
        collectSpecFiles(*errorstream);
        loader = customLoader_;
    }

    void postSpecFile() override {
        ghidra_decompiler::Architecture::postSpecFile();
    }
};

struct DecompInterface::Impl {
    Program* program;
    LoadImageFromProgram* loader;  // NOT owned — ownership transfers to Architecture
    std::unique_ptr<ProgramArch> arch;
    ghidra_decompiler::DocumentStorage store;
    bool archInitialized;
    std::map<uint64_t, std::string> symbolNames;

    Impl() : program(nullptr), loader(nullptr), archInitialized(false) {}

    bool setup(Program* prog) {
        if (!s_libraryInitialized) {
            if (!DecompInterface::initializeLibrary())
                return false;
        }

        program = prog;
        if (!program || !program->getMemory()) return false;

        Memory* mem = program->getMemory();
        AddressFactory* af = program->getAddressFactory();
        ghidra::AddressSpace* gSpace = af ? const_cast<ghidra::AddressSpace*>(
            af->getDefaultAddressSpace()) : nullptr;

        LanguageID lid = program->getLanguageID();
        std::string langId = lid.getIdAsString();
        if (langId.empty() || langId == "unknown")
            langId = "x86:LE:64:default";

        auto* rawLoader = new LoadImageFromProgram(program->getName(), mem, gSpace);
        loader = rawLoader;
        arch = std::make_unique<ProgramArch>(
            program->getName(), langId, &std::cerr, rawLoader);

        try {
            arch->init(store);
        } catch (const ghidra_decompiler::LowlevelError& le) {
            std::cerr << "DecompInterface: Architecture init failed: " << le.explain << std::endl;
            return false;
        } catch (const std::exception& e) {
            std::cerr << "DecompInterface: Architecture init failed: " << e.what() << std::endl;
            return false;
        }

        // Enable calling convention display
        for (auto& mp : arch->protoModels)
            mp.second->setPrintInDecl(true);
        if (arch->defaultfp)
            arch->defaultfp->setPrintInDecl(true);

        // Build symbol map from Program functions and register them
        FunctionManager* fm = program->getFunctionManager();
        if (fm) {
            FunctionIterator fit = fm->getFunctions(true);
            while (fit.hasNext()) {
                Function* func = fit.next();
                if (!func) continue;
                uint64_t off = func->getEntryPoint().getOffset();
                std::string name = func->getName();
                if (off != 0 && !name.empty())
                    symbolNames[off] = name;
            }
        }

        // Pre-register known function symbols in decompiler's symbol table
        ghidra_decompiler::AddrSpace* codeSpace = arch->getDefaultCodeSpace();
        if (codeSpace) {
            for (const auto& pair : symbolNames) {
                if (pair.first == 0 || pair.second.empty()) continue;
                ghidra_decompiler::Address sAddr(codeSpace,
                    static_cast<ghidra_decompiler::int8>(pair.first));
                arch->symboltab->getGlobalScope()->addFunction(sAddr, pair.second);
            }
        }

        // Set up PrintC symbol provider so output uses real function names
        if (auto* pc = dynamic_cast<ghidra_decompiler::PrintC*>(arch->print)) {
            auto* symNames = &symbolNames;
            pc->setSymbolProvider([symNames](const ghidra_decompiler::Address& addr) {
                uint64_t off = addr.getOffset();
                auto it = symNames->find(off);
                return (it != symNames->end()) ? it->second : std::string("");
            });

            // Set up variable name provider for data-flow naming of globals
            Memory* varMem = mem;
            auto* varSpace = const_cast<ghidra::AddressSpace*>(
                af ? af->getDefaultAddressSpace() : nullptr);
            auto* varFuncNames = &symbolNames;
            pc->setVariableNameProvider([varMem, varSpace, varFuncNames](
                const ghidra_decompiler::Address& addr, ghidra_decompiler::int4 size) -> std::string {
                // Only rename global (non-stack) unnamed variables
                if (addr.getSpace()->getType() == ghidra_decompiler::IPTR_SPACEBASE)
                    return "";
                if (!varMem || !varSpace) return "";
                uint64_t offset = addr.getOffset();
                // Read the VALUE stored at this global variable's address
                uint8_t raw[8] = {0};
                int readSz = size > 8 ? 8 : size;
                ghidra::Address gAddr(varSpace, static_cast<int64_t>(offset));
                int n = 0;
                try { n = varMem->getBytes(gAddr, raw, readSz); } catch (...) { return ""; }
                if (n < 1) return "";
                // Interpret as little-endian unsigned value
                uint64_t val = 0;
                for (int i = n - 1; i >= 0; --i)
                    val = (val << 8) | raw[i];
                if (val == 0) return "";
                // Check if the value is a known function address
                if (varFuncNames) {
                    auto fnIt = varFuncNames->find(val);
                    if (fnIt != varFuncNames->end()) {
                        std::string fn = fnIt->second;
                        if (!fn.empty())
                            return "p_" + fn;
                    }
                }
                // Check if the value points to a readable ASCII string
                ghidra::Address ptrAddr(varSpace, static_cast<int64_t>(val));
                uint8_t strBuf[48] = {0};
                int strN = 0;
                try { strN = varMem->getBytes(ptrAddr, strBuf, 48); } catch (...) { return ""; }
                if (strN > 0) {
                    bool printable = true;
                    int slen = 0;
                    for (int i = 0; i < strN; ++i) {
                        if (strBuf[i] == 0) break;
                        if (!std::isprint(strBuf[i])) { printable = false; break; }
                        ++slen;
                    }
                    if (printable && slen >= 2) {
                        std::string s;
                        for (int i = 0; i < slen && i < 24; ++i)
                            s.push_back(strBuf[i]);
                        std::string safe;
                        safe.reserve(s.size());
                        for (char c : s)
                            safe.push_back(std::isalnum(c) ? c : '_');
                        return "s_" + safe;
                    }
                }
                return "";
            });
        }

        // Bridge analysis results and API import signatures into the decompiler.
        // Gives imported functions typed parameters (e.g. VirtualProtect takes
        // LPVOID, SIZE_T, DWORD, PDWORD) so call sites show real types.
        if (auto* progDB = dynamic_cast<ghidra::ProgramDB*>(program)) {
            uint64_t imgBase = program->getImageBase().getOffset();
            ghidra::AnalysisBridge bridge(progDB, arch.get(), symbolNames,
                imgBase, imgBase, false);

            std::unique_ptr<ghidra::TypeDatabase> typeDB;
            std::string fmt = program->getExecutableFormat();
            for (auto& c : fmt) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (fmt.find("PE") != std::string::npos)
                typeDB = ghidra::createWindowsTypeDatabase();
            else if (fmt.find("ELF") != std::string::npos)
                typeDB = ghidra::createLinuxTypeDatabase();
            else if (fmt.find("MACH-O") != std::string::npos ||
                     fmt.find("FAT") != std::string::npos ||
                     fmt.find("PEF") != std::string::npos)
                typeDB = ghidra::createMacOSTypeDatabase();

            if (typeDB) bridge.setTypeDatabase(typeDB.get());

            try {
                bridge.bridgeFunctions();
                bridge.bridgeTypes();
                bridge.bridgeImportSignatures();
                bridge.bridgeNoReturnFlags();
                bridge.bridgeLabels();
                bridge.bridgeReadOnlyRanges();
            } catch (const std::exception& e) {
                std::cerr << "DecompInterface: type bridge failed: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "DecompInterface: type bridge failed (unknown exception)\n";
            }
        }

        archInitialized = true;
        return true;
    }

    DecompileResults decompile(const Address& entryPoint, TaskMonitor* monitor) {
        DecompileResults results;
        results.entryPoint = entryPoint;

        if (!archInitialized || !arch) {
            results.decompiled = false;
            return results;
        }

        ghidra_decompiler::AddrSpace* codeSpace = arch->getDefaultCodeSpace();
        if (!codeSpace) {
            results.decompiled = false;
            return results;
        }

        uint64_t entryOff = entryPoint.getOffset();
        if (program && program->getMemory()) {
            try {
                if (!program->getMemory()->getBlock(entryPoint)) {
                    results.decompiled = false;
                    return results;
                }
            } catch (...) {
                results.decompiled = false;
                return results;
            }
        }

        ghidra_decompiler::Address decAddr(codeSpace,
            static_cast<ghidra_decompiler::int8>(entryOff));

        if (monitor)
            monitor->setMessage("Decompiling function at 0x" + std::to_string(entryOff));

    ghidra_decompiler::Funcdata* fd = nullptr;
    try {
        fd = arch->symboltab->getGlobalScope()->queryFunction(decAddr);
            if (!fd) {
                std::string funcName = "entry";
                FunctionManager* fm = program ? program->getFunctionManager() : nullptr;
                if (fm) {
                    Address progAddr = entryPoint;
                    Function* progFunc = fm->getFunctionAt(progAddr);
                    if (progFunc) {
                        std::string n = progFunc->getName();
                        if (!n.empty()) funcName = n;
                    }
                }

                auto* fsym = arch->symboltab->getGlobalScope()->addFunction(decAddr, funcName);
                if (!fsym) {
                    results.decompiled = false;
                    return results;
                }
                fd = fsym->getFunction();
            }
        } catch (const ghidra_decompiler::LowlevelError& le) {
            if (monitor) monitor->setMessage("Function lookup error: " + le.explain);
            results.decompiled = false;
            return results;
        } catch (const std::exception& e) {
            if (monitor) monitor->setMessage("Function lookup error: " + std::string(e.what()));
            results.decompiled = false;
            return results;
        }
        if (!fd) {
            results.decompiled = false;
            return results;
        }

        try {
            arch->clearAnalysis(fd);
            arch->allacts.getCurrent()->reset(*fd);
            arch->allacts.getCurrent()->perform(*fd);
        } catch (const ghidra_decompiler::LowlevelError& le) {
            if (monitor) monitor->setMessage("Decompile error: " + le.explain);
            results.decompiled = false;
            return results;
        } catch (const std::exception& e) {
            if (monitor) monitor->setMessage("Decompile error: " + std::string(e.what()));
            results.decompiled = false;
            return results;
        } catch (...) {
            if (monitor) monitor->setMessage("Decompile error: unknown exception");
            results.decompiled = false;
            return results;
        }

        results.decompiled = fd->isProcStarted() && !fd->hasNoCode();
        if (!results.decompiled) return results;

        results.functionName = fd->getName();
        results.functionSize = fd->getSize();

        const ghidra_decompiler::FuncProto& proto = fd->getFuncProto();
        if (proto.hasModel())
            results.conventionName = proto.getModelName();
        results.stackPurgeSize = proto.getExtraPop();

        ghidra::AddressSpace* gSpace = program
            ? const_cast<ghidra::AddressSpace*>(
                program->getAddressFactory()->getDefaultAddressSpace())
            : nullptr;
        for (ghidra_decompiler::int4 i = 0; i < fd->numCalls(); ++i) {
            ghidra_decompiler::FuncCallSpecs* fc = fd->getCallSpecs(i);
            if (!fc) continue;
            DecompiledCall call;
            if (gSpace) {
                ghidra::Address callAddr(gSpace,
                    static_cast<int64_t>(fc->getEntryAddress().getOffset()));
                call.entryAddress = callAddr;
            }
            call.name = fc->getName();
            call.stackPurgeSize = fc->getEffectiveExtraPop();
            results.calls.push_back(call);
        }
        results.callCount = static_cast<int>(results.calls.size());

        const ghidra_decompiler::BlockGraph& blockGraph = fd->getBasicBlocks();
        for (ghidra_decompiler::int4 i = 0; i < blockGraph.getSize(); ++i) {
            ghidra_decompiler::FlowBlock* fb = blockGraph.getBlock(i);
            ghidra_decompiler::BlockBasic* block = dynamic_cast<ghidra_decompiler::BlockBasic*>(fb);
            if (!block) continue;
            for (auto iter = block->beginOp(); iter != block->endOp(); ++iter) {
                ghidra_decompiler::PcodeOp* op = *iter;
                if (!op) continue;
                uint64_t opref = static_cast<uint64_t>(op->getTime());
                uint64_t opaddr = static_cast<uint64_t>(op->getSeqNum().getAddr().getOffset());
                if (opref != 0 && opaddr != 0)
                    results.opAddresses.push_back({opref, opaddr});
            }
        }

        std::ostringstream xmlStream;
        try {
            arch->print->setOutputStream(&xmlStream);
            arch->print->setMarkup(true);
            arch->print->setPackedOutput(false);
            arch->print->docFunction(fd);
        } catch (const std::exception& e) {
            if (monitor) monitor->setMessage("C code generation error: " + std::string(e.what()));
            results.decompiled = false;
            return results;
        } catch (...) {
            if (monitor) monitor->setMessage("C code generation error: unknown exception");
            results.decompiled = false;
            return results;
        }
        std::string markup = xmlStream.str();
        results.markupXml = markup;
        // Resolve string literal references (char *)0xHEX -> "string"
        uint64_t imgBase = program ? program->getImageBase().getOffset() : 0;
        ghidra::Memory* mem = program ? program->getMemory() : nullptr;
        ghidra::AddressSpace* defSpace = program
            ? const_cast<ghidra::AddressSpace*>(
                program->getAddressFactory()->getDefaultAddressSpace())
            : nullptr;
        if (mem && defSpace) {
            markup = resolveStringRefsInMarkup(markup, mem, defSpace, imgBase);
        }
        results.cCode = cleanCOutput(stripMarkup(markup));

        return results;
    }

    std::vector<DecompFunctionSummary> listFunctions() const {
        std::vector<DecompFunctionSummary> result;
        if (!program) return result;

        FunctionManager* fm = program->getFunctionManager();
        if (!fm) return result;

        FunctionIterator fit = fm->getFunctions(true);
        while (fit.hasNext()) {
            Function* func = fit.next();
            if (!func) continue;

            DecompFunctionSummary item;
            item.entryAddress = func->getEntryPoint();
            item.name = func->getName();
            item.bodyAddressCount = static_cast<int>(func->getBody().getNumAddresses());
            item.external = func->isExternal();
            item.thunk = func->isThunk();
            result.push_back(item);
        }
        return result;
    }
};

DecompileResults::DecompileResults()
    : decompiled(false), functionSize(0), stackPurgeSize(0), callCount(0) {}

DecompInterface::DecompInterface()
    : impl(std::make_unique<Impl>()) {}

DecompInterface::~DecompInterface() {
    closeProgram();
}

bool DecompInterface::openProgram(Program* program) {
    closeProgram();
    return impl->setup(program);
}

void DecompInterface::closeProgram() {
    impl->arch.reset();    // Architecture destructor deletes the loader
    impl->loader = nullptr;
    impl->program = nullptr;
    impl->archInitialized = false;
    impl->symbolNames.clear();
}

bool DecompInterface::isOpen() const {
    return impl->archInitialized && impl->program != nullptr;
}

void DecompInterface::refreshFunctionSymbols() {
    if (!impl->archInitialized || !impl->arch || !impl->program) return;
    Program* saved = impl->program;
    closeProgram();
    openProgram(saved);
}

std::vector<DecompFunctionSummary> DecompInterface::getFunctions() const {
    return impl->listFunctions();
}

DecompileResults DecompInterface::decompileFunction(const Address& entryPoint, TaskMonitor* monitor) {
    return impl->decompile(entryPoint, monitor);
}

DecompileResults DecompInterface::decompileFunction(Function* function, TaskMonitor* monitor) {
    if (!function) return DecompileResults();
    return impl->decompile(function->getEntryPoint(), monitor);
}

struct AsmEmit : ghidra_decompiler::AssemblyEmit {
    std::ostringstream& out;
    AsmEmit(std::ostringstream& s) : out(s) {}
    void dump(const ghidra_decompiler::Address& addr, const std::string& mnem, const std::string& body) override {
        auto off = addr.getOffset();
        out << "0x" << std::hex << off << std::dec << ":  " << mnem;
        if (!body.empty()) out << "  " << body;
        out << "\n";
    }
};

std::string DecompInterface::disassembleAt(const Address& addr, int numInstructions) {
    return disassembleAt(addr, numInstructions, 0);
}

std::string DecompInterface::disassembleAt(const Address& addr, int numInstructions, int maxBytes) {
    if (!impl->archInitialized || !impl->arch || !impl->arch->translate) {
        return "; No disassembler available";
    }
    std::ostringstream out;
    AsmEmit emit(out);
    const ghidra_decompiler::Translate* trans = impl->arch->translate;
    ghidra_decompiler::AddrSpace* space = impl->arch->getDefaultCodeSpace();
    if (!space) return "; No code space";

    uint64_t offset = addr.getOffset();
    uint64_t endOffset = (maxBytes > 0) ? offset + maxBytes : 0;
    int errorCount = 0;
    const int maxErrors = 100;
    for (int i = 0; i < numInstructions; i++) {
        if (endOffset > 0 && offset >= endOffset) break;
        try {
            ghidra_decompiler::Address decAddr(space, static_cast<ghidra_decompiler::int8>(offset));
            ghidra_decompiler::int4 len = trans->printAssembly(emit, decAddr);
            if (len <= 0) {
                if (errorCount == 0)
                    std::cerr << "[disassembleAt] first decode failure at 0x" << std::hex << offset << std::dec << std::endl;
                if (++errorCount >= maxErrors) break;
                offset++;
                continue;
            }
            offset += len;
        } catch (const ghidra_decompiler::LowlevelError& le) {
            if (errorCount == 0)
                std::cerr << "[disassembleAt] first error at 0x" << std::hex << offset << ": " << le.explain << std::dec << std::endl;
            if (++errorCount >= maxErrors) break;
            offset++;
        } catch (const std::exception& e) {
            if (errorCount == 0)
                std::cerr << "[disassembleAt] first exception at 0x" << std::hex << offset << ": " << e.what() << std::dec << std::endl;
            if (++errorCount >= maxErrors) break;
            offset++;
        }
    }
    if (errorCount > 0) {
        std::cerr << "[disassembleAt] skipped " << errorCount << " unresolvable bytes at 0x" << std::hex << addr.getOffset() << std::dec << std::endl;
    }

    std::string result = out.str();
    if (result.empty()) {
        std::cerr << "[disassembleAt] WARNING: returning empty string for addr=0x" << std::hex << addr.getOffset()
                  << " offset=0x" << offset << " space=" << space->getName() << std::dec << std::endl;
    }
    return result;
}

int DecompInterface::instructionLengthAt(uint64_t offset) const {
    if (!impl || !impl->archInitialized || !impl->arch) return 0;
    ghidra_decompiler::AddrSpace* space = impl->arch->getDefaultCodeSpace();
    if (!space) return 0;
    ghidra_decompiler::Address addr(space, offset);
    return impl->arch->translate->instructionLength(addr);
}

bool DecompInterface::initializeLibrary() {
    std::lock_guard<std::mutex> lock(s_initMutex);
    if (s_libraryInitialized) return true;

    try {
        ghidra_decompiler::AttributeId::initialize();
        ghidra_decompiler::ElementId::initialize();
        ghidra_decompiler::CapabilityPoint::initializeAll();
        ghidra_decompiler::ArchitectureCapability::sortCapabilities();

        volatile auto pcc = &ghidra_decompiler::PrintCCapability::printCCapability;
        (void)pcc;

        std::string sleighDir = registerSleighPaths();
        if (sleighDir.empty()) {
            std::cerr << "DecompInterface: No SLEIGH specs found. Set ENIGMA_SLEIGH_DIR." << std::endl;
            return false;
        }
        s_libraryInitialized = true;
        return true;
    } catch (const ghidra_decompiler::LowlevelError& le) {
        std::cerr << "DecompInterface: Library init failed: " << le.explain << std::endl;
        return false;
    }
}

void DecompInterface::shutdownLibrary() {
    std::lock_guard<std::mutex> lock(s_initMutex);
    s_libraryInitialized = false;
}

} // namespace ghidra
