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
#include <cstring>
#include <mutex>
#include <sstream>
#include <set>

namespace ghidra {

static std::mutex s_initMutex;
static bool s_libraryInitialized = false;

static std::string cleanCOutput(const std::string& raw) {
    std::string s = raw;
    for (size_t pos = 0; (pos = s.find("{\n\n", pos)) != std::string::npos; ) {
        s.replace(pos, 3, "{\n");
        pos += 2;
    }
    for (size_t pos = 0; (pos = s.find("(void)", pos)) != std::string::npos; ) {
        s.replace(pos, 6, "()");
        pos += 2;
    }
    for (size_t pos = 0; (pos = s.find("xunknown", pos)) != std::string::npos; ) {
        s.replace(pos, 8, "undefined");
        pos += 9;
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
        if (memory_)
            nread = memory_->getBytes(gAddr, ptr, size);
        if (nread < size)
            std::memset(ptr + nread, 0, size - nread);
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

        std::string langId = "x86:LE:64:default";
        Language* lang = program->getLanguage();
        if (lang) {
            LanguageID lid = lang->getLanguageID();
            std::string lidStr = lid.getIdAsString();
            if (!lidStr.empty()) langId = lidStr;
        }

        auto* rawLoader = new LoadImageFromProgram(program->getName(), mem, gSpace);
        loader = rawLoader;
        arch = std::make_unique<ProgramArch>(
            program->getName(), langId, &std::cerr, rawLoader);

        try {
            arch->init(store);
        } catch (const ghidra_decompiler::LowlevelError& le) {
            std::cerr << "DecompInterface: Architecture init failed: " << le.explain << std::endl;
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

        ghidra_decompiler::Funcdata* fd =
            arch->symboltab->getGlobalScope()->queryFunction(decAddr);
        if (!fd) {
            // Check Program's FunctionManager for a name first
            std::string funcName = "FUN_ENTRY";
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

        std::ostringstream cStream;
        arch->print->setOutputStream(&cStream);
        arch->print->docFunction(fd);
        results.cCode = cleanCOutput(cStream.str());

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
        std::ios_base::fmtflags f(out.flags());
        out << "0x" << std::hex << off << ":  " << mnem;
        if (!body.empty()) out << "  " << body;
        out << "\n";
        out.flags(f);
    }
};

std::string DecompInterface::disassembleAt(const Address& addr, int numInstructions) {
    if (!impl->archInitialized || !impl->arch || !impl->arch->translate) {
        return "; No disassembler available";
    }
    std::ostringstream out;
    AsmEmit emit(out);
    const ghidra_decompiler::Translate* trans = impl->arch->translate;
    ghidra_decompiler::AddrSpace* space = impl->arch->getDefaultCodeSpace();
    if (!space) return "; No code space";

    uint64_t offset = addr.getOffset();
    for (int i = 0; i < numInstructions; i++) {
        ghidra_decompiler::Address decAddr(space, static_cast<ghidra_decompiler::int8>(offset));
        ghidra_decompiler::int4 len = trans->printAssembly(emit, decAddr);
        if (len <= 0) break;
        offset += len;
    }
    return out.str();
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
