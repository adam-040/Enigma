#include <ghidra/EnigmaPipeline.h>
#include <ghidra/BinaryLoader.h>
#include <iostream>
#include <string>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cctype>
#include <vector>
#include <cstdint>
#include <memory>
#include <algorithm>
#include <functional>
#include <limits>
#include <set>
#include <deque>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <chrono>

// Decompiler headers
#include <libdecomp.hh>
#include <sleigh_arch.hh>
#include <raw_arch.hh>
#include <loadimage.hh>
#include <printc.hh>

// ProgramDB + Analyzer headers (DWARF name extraction)
#include <ghidra/ProgramDB.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AnalysisBridge.h>
#include <ghidra/TypeDatabase.h>

using namespace ghidra_decompiler;

static void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options] <binary>\n"
              << "Options:\n"
              << "  -lang <id>     Language ID [default: x86:LE:64:default]\n"
              << "  -base <addr>   VMA for file offset 0 (hex) [default: 0x140001000]\n"
              << "  -entry <addr>  Entry point address (hex, default = -base)\n"
              << "  -o <file>      Write output to file instead of stdout\n"
              << "  -time          Print decompilation timing breakdown\n"
              << "  -max-func <N>  Limit total decompiled functions (default: 200)\n"
              << "  -no-crt       Do not suppress CRT/library function boundary\n"
              << "  -no-bridge    Skip all ProgramDB→decompiler bridging\n"
              << "  -no-type-bridge  Skip type bridge only\n"
              << "  -raw-types    Preserve undefined1/2/4/8 (skip uintN_t normalization)\n"
              << "  -h             Print this help\n";
}

static std::vector<std::filesystem::path> getSleighCandidates() {
    std::vector<std::filesystem::path> candidates;
    auto add = [&](const std::filesystem::path& p) {
        if (!p.empty() && std::find(candidates.begin(), candidates.end(), p) == candidates.end())
            candidates.emplace_back(p);
    };
    if (const char* envPath = std::getenv("ENIGMA_SLEIGH_DIR")) {
        if (*envPath != '\0') add(std::filesystem::path(envPath));
    }
#ifndef ENIGMA_SLEIGH_DIR
#define ENIGMA_SLEIGH_DIR ""
#endif
    if (std::string compilePath = ENIGMA_SLEIGH_DIR; !compilePath.empty()) {
        add(std::filesystem::path(compilePath));
    }
    std::error_code ec;
    auto cwdSleigh = std::filesystem::current_path(ec) / "sleigh";
    if (!ec && std::filesystem::is_directory(cwdSleigh, ec)) {
        add(cwdSleigh);
    }
    return candidates;
}

static bool hasLanguageDefinition(const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return false;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!ec && entry.is_regular_file(ec) && entry.path().extension() == ".ldefs")
            return true;
    }
    return false;
}

static std::string registerSleighSpecs() {
    for (const auto& root : getSleighCandidates()) {
        std::error_code ec;
        if (!std::filesystem::is_directory(root, ec)) continue;
        if (hasLanguageDefinition(root)) {
            SleighArchitecture::scanForSleighDirectories(root.string());
        }
        bool registeredAny = hasLanguageDefinition(root);
        for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
            if (ec) break;
            if (entry.is_directory(ec) && hasLanguageDefinition(entry.path())) {
                SleighArchitecture::scanForSleighDirectories(entry.path().string());
                registeredAny = true;
            }
        }
        if (registeredAny) return root.string();
    }
    return {};
}

static uint64_t inferLoaderBase(const ghidra::BinaryLoader& loader) {
    uint64_t base = loader.getImageBase();
    if (base != 0)
        return base;

    uint64_t inferred = std::numeric_limits<uint64_t>::max();
    for (const auto& section : loader.getSections()) {
        if (section.virtualAddress == 0)
            continue;
        if (std::max(section.virtualSize, section.fileSize) == 0)
            continue;
        inferred = std::min(inferred, section.virtualAddress);
    }
    return inferred == std::numeric_limits<uint64_t>::max() ? 0 : inferred;
}

// LoadImage from raw file - extends RawLoadImage for compatibility with postSpecFile()
class FileLoadImage : public RawLoadImage {
    vector<uint1> data_;
    uintb baseAddr_;
public:
    FileLoadImage(const string& path, uintb base)
        : RawLoadImage(path), baseAddr_(base) {
        ifstream f(path, ios::binary | ios::ate);
        if (!f) return;
        uint64_t sz = std::filesystem::file_size(path);
        f.seekg(0, ios::beg);
        data_.resize(static_cast<size_t>(sz));
        f.read(reinterpret_cast<char*>(data_.data()), sz);
    }
    void loadFill(uint1* ptr, int4 size, const Address& addr) override {
        if (addr.getOffset() < baseAddr_) {
            memset(ptr, 0, size);
            return;
        }
        uintb offset = addr.getOffset() - baseAddr_;
        if (offset < data_.size()) {
            uintb available = data_.size() - offset;
            int4 toCopy = static_cast<int4>(std::min(static_cast<uintb>(size), available));
            memcpy(ptr, data_.data() + static_cast<size_t>(offset), toCopy);
            if (toCopy < size) memset(ptr + toCopy, 0, size - toCopy);
        } else {
            memset(ptr, 0, size);
        }
    }
    string getArchType(void) const override { return "raw"; }
    void adjustVma(long adj) override { baseAddr_ += adj; }
    uintb getBase() const { return baseAddr_; }
};

// Post-process decompiler output for non-semantic formatting
static std::string cleanOutput(const std::string& raw, bool skipTypeNorm = false) {
    std::string s = raw;
    
    // 1. Strip extra blank lines after opening braces
    {
        for (size_t pos = 0; (pos = s.find("{\n\n", pos)) != std::string::npos; ) {
            s.replace(pos, 3, "{\n");
            pos += 2;
        }
    }

    // 2. Replace (void) with () in parameter lists
    {
        for (size_t pos = 0; (pos = s.find("(void)", pos)) != std::string::npos; ) {
            s.replace(pos, 6, "()");
            pos += 2;
        }
    }

    // 2b. Normalize " ()" -> "()" (remove space before empty parens)
    {
        for (size_t pos = 0; (pos = s.find(" ()", pos)) != std::string::npos; ) {
            s.replace(pos, 3, "()");
            pos += 2;
        }
    }

    // 2c. Remove space before '(' in function calls: "func (arg)" -> "func(arg)"
    {
        for (size_t pos = 0; (pos = s.find(" (", pos)) != std::string::npos; ) {
            if (pos > 0 && (std::isalnum(s[pos-1]) || s[pos-1] == '_' || s[pos-1] == ')')) {
                size_t start = pos;
                while (start > 0 && (std::isalnum(s[start-1]) || s[start-1] == '_')) start--;
                std::string word = s.substr(start, pos - start);
                if (word != "if" && word != "while" && word != "for" && word != "switch" &&
                    word != "return" && word != "sizeof" && word != "case" && word != "do") {
                    s.erase(pos, 1);
                    continue;
                }
            }
            pos += 2;
        }
    }

    // 3. Strip noisy WARNING comments (e.g., "Globals starting with '_' overlap...")
    {
        for (size_t pos = 0; (pos = s.find("/* WARNING:", pos)) != std::string::npos; ) {
            size_t end = s.find("*/", pos + 11);
            if (end == std::string::npos) { pos += 11; continue; }
            end += 2;
            // Remove the warning line including its trailing newline
            size_t lineEnd = s.find('\n', end);
            if (lineEnd != std::string::npos && lineEnd == end - 1) {
                // Warning is its own line, remove it entirely
                size_t lineStart = (pos > 0) ? s.rfind('\n', pos - 1) : std::string::npos;
                if (lineStart != std::string::npos && lineStart >= pos) lineStart = pos;
                size_t removeEnd = lineEnd + 1;
                if (lineStart == std::string::npos) {
                    s.erase(pos, removeEnd - pos);
                    pos = 0;
                } else {
                    s.erase(lineStart + 1, removeEnd - lineStart - 1);
                    pos = lineStart + 1;
                }
            } else {
                // Inline warning, just remove the comment
                s.erase(pos, end - pos);
            }
        }
    }

    // 4. Normalize unknown-size types to standard C fixed-width types.
    //    undefined1/2/4/8 become uint8_t/uint16_t/uint32_t/uint64_t.
    //    Skipped when skipTypeNorm is true (for type audit purposes).
    if (!skipTypeNorm) {
        static const char* undefs[] = {"undefined8", "undefined4", "undefined2", "undefined1"};
        static const char* fixed[]  = {"uint64_t",    "uint32_t",    "uint16_t",    "uint8_t"};
        for (int i = 0; i < 4; ++i) {
            size_t flen = std::strlen(undefs[i]);
            size_t tlen = std::strlen(fixed[i]);
            for (size_t pos = 0; (pos = s.find(undefs[i], pos)) != std::string::npos; ) {
                s.replace(pos, flen, fixed[i]);
                pos += tlen;
            }
        }
    }

    return s;
}



// Resolve string constant references in decompiler output.
// Finds patterns like (char *)0xHEX in function arguments and replaces
// with quoted string literals when the target address contains printable ASCII.
static std::string resolveStringRefs(const std::string& raw,
                                     const std::vector<uint8_t>& binaryData,
                                     uint64_t baseAddr, uint64_t originalBase) {
    std::string s = raw;
    // Match: (char *)0xHEXDIGITS — the common pattern for string pointer args
    // Also match: (char const*)0xHEX, (const char *)0xHEX, (char const *)0xHEX
    const char* patterns[] = {
        "(char *)0x",
        "(char const*)0x",
        "(const char *)0x",
        "(char const *)0x",
    };
    uint64_t baseForData = (originalBase != 0) ? originalBase : baseAddr;
    // Map virtual address to binary offset
    auto addrToOffset = [&](uint64_t addr) -> int64_t {
        if (addr < baseForData) return -1;
        uint64_t delta = addr - baseForData;
        if (delta >= binaryData.size()) return -1;
        return static_cast<int64_t>(delta);
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
            int64_t fileOff = addrToOffset(addr);
            if (fileOff < 0) { pos = end; continue; }
            // Read null-terminated string, limit to 256 chars
            std::string strContent;
            bool printable = true;
            for (int64_t i = fileOff; i < static_cast<int64_t>(binaryData.size()) && i < fileOff + 256; ++i) {
                uint8_t c = binaryData[i];
                if (c == 0) break;
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

// Build address → name map for post-processing unresolved func_0x... and sub_0x... references
static std::string resolveFuncRefs(const std::string& raw,
                                   const std::map<uint64_t, std::string>& symNames) {
    std::string s = raw;
    for (const char* prefix : {"function_0x", "func_0x", "sub_0x"}) {
        size_t plen = std::strlen(prefix);
        for (size_t pos = 0; (pos = s.find(prefix, pos)) != std::string::npos; ) {
            size_t end = pos + plen;
            while (end < s.size() && std::isxdigit(static_cast<unsigned char>(s[end])))
                ++end;
            if (end == pos + plen) { pos = end; continue; }
            std::string hexStr = s.substr(pos + plen, end - (pos + plen));
            if (hexStr.empty()) { pos = end; continue; }
            uint64_t addr = std::stoull(hexStr, nullptr, 16);
            auto it = symNames.find(addr);
            if (it != symNames.end()) {
                s.replace(pos, end - pos, it->second);
                pos += it->second.size();
            } else {
                // Normalize function_0x to sub_0x (strip leading zeros)
                bool isFuncPrefix = (*prefix == 'f');
                if (isFuncPrefix) {
                    std::string canonical;
                    if (addr == 0) {
                        canonical = "sub_0x0";
                    } else {
                        std::ostringstream oss;
                        oss << "sub_0x" << std::hex << addr;
                        canonical = oss.str();
                    }
                    s.replace(pos, end - pos, canonical);
                    pos += canonical.size();
                } else {
                    pos = end;
                }
            }
        }
    }
    return s;
}

// Minimal architecture wrapper
class SimpleBinaryArch : public RawBinaryArchitecture {
    LoadImage* customLoader_;
public:
    SimpleBinaryArch(const string& fname, const string& targ, ostream* estream, LoadImage* loader)
        : RawBinaryArchitecture(fname, targ, estream), customLoader_(loader) {}
    void buildLoader(DocumentStorage& store) override {
        collectSpecFiles(*errorstream);
        loader = customLoader_;
    }
    void postSpecFile(void) override {
        Architecture::postSpecFile();
        // Skip RawBinaryArchitecture::postSpecFile() which casts to RawLoadImage*
        // Our loaders (FileLoadImage, BinaryLoaderLoadImage) handle their own space
    }
};

// LoadImage backed by BinaryLoader for PE/ELF auto-detection
class BinaryLoaderLoadImage : public LoadImage {
    std::unique_ptr<ghidra::BinaryLoader> bloader_;
    uintb originalBase_;
    uintb mappedBase_;
    bool rebase_;
    // Mutable iteration state for const open/getNext/close methods
    mutable std::vector<std::pair<std::string,uint64_t>> symbolList_;
    mutable size_t symbolIdx_;
    mutable std::vector<ghidra::SectionInfo> sections_;
    mutable size_t sectionIdx_;
public:
    BinaryLoaderLoadImage(const string& fname, std::unique_ptr<ghidra::BinaryLoader> loader,
                          uintb originalBase, uintb mappedBase, bool rebase)
        : LoadImage(fname), bloader_(std::move(loader)), originalBase_(originalBase),
          mappedBase_(mappedBase), rebase_(rebase && originalBase != mappedBase),
          symbolIdx_(0), sectionIdx_(0) {}
    void loadFill(uint1* ptr, int4 size, const Address& addr) override {
        uintb mappedOffset = addr.getOffset();
        uintb loaderOffset = mappedOffset;
        if (rebase_ && mappedOffset >= mappedBase_)
            loaderOffset = originalBase_ + (mappedOffset - mappedBase_);
        auto bytes = bloader_->getBytes(loaderOffset, size);
        int4 copySize = static_cast<int4>(bytes.size());
        if (copySize > size) copySize = size;
        memcpy(ptr, bytes.data(), copySize);
        if (copySize < size)
            memset(ptr + copySize, 0, size - copySize);
    }
    string getArchType() const override { return "raw"; }
    void adjustVma(long adjust) override { mappedBase_ += adjust; }
    void openSymbols() const override {}
    void closeSymbols() const override {}
    bool getNextSymbol(LoadImageFunc& record) const override { return false; }
    void openSectionInfo() const override {}
    void closeSectionInfo() const override {}
    bool getNextSection(LoadImageSection& sec) const override { return false; }
    void getReadonly(RangeList& list) const override {}
};

/// Apply TypeDatabase prototypes to all call sites within a decompiled function.
/// This handles DIRECT imports (IAT calls) where CALLIND couldn't resolve a prototype.
/// Must run AFTER the action pipeline (perform) but BEFORE print (docFunction).
static void applyTypeDatabaseToCallSpecs(Funcdata* fd, ghidra::TypeDatabase* typeDB,
    ghidra_decompiler::TypeFactory* tf, ghidra_decompiler::Architecture* arch)
{
    if (!fd || !typeDB) return;

    // --- resolveTypeName: maps Windows type names → decompiler Datatype* ---
    int4 ptrSize = tf->getSizeOfPointer();
    auto resolveTypeName = [tf, ptrSize](const std::string& tn) -> Datatype* {
        if (tn.empty() || tn == "void") return tf->getTypeVoid();
        // --- unsigned integer types ---
        if (tn == "BOOL" || tn == "BOOLEAN" || tn == "BYTE" || tn == "UCHAR") return tf->getBase(1, TYPE_UINT);
        if (tn == "WORD" || tn == "USHORT" || tn == "WCHAR" || tn == "OLECHAR") return tf->getBase(2, TYPE_UINT);
        if (tn == "DWORD" || tn == "UINT" || tn == "ULONG" || tn == "DWORD32") return tf->getBase(4, TYPE_UINT);
        if (tn == "DWORD64" || tn == "ULONGLONG" || tn == "QWORD" || tn == "ULONG64") return tf->getBase(8, TYPE_UINT);
        if (tn == "DWORD_PTR" || tn == "ULONG_PTR" || tn == "SIZE_T" || tn == "LPARAM" || tn == "WPARAM" || tn == "LRESULT") return tf->getBase(ptrSize, TYPE_UINT);
        if (tn == "UINT_PTR") return tf->getBase(ptrSize, TYPE_UINT);
        // --- signed integer types ---
        if (tn == "CHAR" || tn == "int8" || tn == "INT8") return tf->getBase(1, TYPE_INT);
        if (tn == "SHORT" || tn == "short" || tn == "INT16") return tf->getBase(2, TYPE_INT);
        if (tn == "int" || tn == "LONG" || tn == "INT" || tn == "INT32") return tf->getBase(4, TYPE_INT);
        if (tn == "LONGLONG" || tn == "LONG64" || tn == "INT64") return tf->getBase(8, TYPE_INT);
        if (tn == "LONG_PTR") return tf->getBase(ptrSize, TYPE_INT);
        // --- floating point ---
        if (tn == "float" || tn == "FLOAT") return tf->getBase(4, TYPE_FLOAT);
        if (tn == "double" || tn == "DOUBLE") return tf->getBase(8, TYPE_FLOAT);
        // --- common typedefs ---
        if (tn == "HANDLE" || tn == "HWND" || tn == "HDC" || tn == "HINSTANCE" || tn == "HMODULE")
            return tf->getTypePointer(ptrSize, tf->getTypeVoid(), ptrSize);
        if (tn == "LPVOID" || tn == "PVOID" || tn == "LPCVOID" || tn == "PVOID64")
            return ptrSize == 8 ? tf->getTypePointer(8, tf->getTypeVoid(), 8) : tf->getTypePointer(4, tf->getTypeVoid(), 4);
        if (tn == "LPSTR" || tn == "LPCSTR") return tf->getTypePointer(ptrSize, tf->getBase(1, TYPE_INT), ptrSize);
        if (tn == "LPWSTR" || tn == "LPCWSTR") return tf->getTypePointer(ptrSize, tf->getBase(2, TYPE_UINT), ptrSize);
        if (tn == "LPDWORD" || tn == "PDWORD" || tn == "PUINT") return tf->getTypePointer(ptrSize, tf->getBase(4, TYPE_UINT), ptrSize);
        if (tn == "HCRYPTPROV" || tn == "HCRYPTKEY" || tn == "HCRYPTHASH") return tf->getTypePointer(ptrSize, tf->getTypeVoid(), ptrSize);
        // --- pointer fallback: names starting with P, LP, or containing * ---
        if (tn.size() > 1 && (tn[0] == 'P' || (tn.size() > 2 && tn[0] == 'L' && tn[1] == 'P')))
            return tf->getTypePointer(ptrSize, tf->getTypeVoid(), ptrSize);
        if (tn.find('*') != std::string::npos) return tf->getTypePointer(ptrSize, tf->getTypeVoid(), ptrSize);
        // --- NTSTATUS / HRESULT ---
        if (tn == "NTSTATUS" || tn == "HRESULT" || tn == "SCODE") return tf->getBase(4, TYPE_INT);
        if (tn == "NET_API_STATUS") return tf->getBase(4, TYPE_UINT);
        return tf->getTypePointer(ptrSize, tf->getTypeVoid(), ptrSize); // void* fallback
    };

    int applied = 0;
    for (int4 i = 0; i < fd->numCalls(); ++i) {
        FuncCallSpecs* fc = fd->getCallSpecs(i);
        if (!fc) continue;
        std::string name = fc->getName();
        if (name.empty()) continue;
        // Skip if already has a convention/model
        if (fc->hasModel()) continue;

        std::string retTypeStr;
        std::vector<std::string> paramTypes;
        if (!typeDB->getFunctionType(name, retTypeStr, paramTypes)) continue;

        Datatype* retType = resolveTypeName(retTypeStr);
        if (!retType) continue;

        std::vector<Datatype*> params;
        bool ok = true;
        for (const auto& pt : paramTypes) {
            Datatype* pdt = resolveTypeName(pt);
            if (!pdt) { ok = false; break; }
            params.push_back(pdt);
        }
        if (!ok) continue;

        PrototypePieces pieces;
        pieces.name = name;
        pieces.outtype = retType;
        pieces.intypes = params;
        pieces.firstVarArgSlot = -1;
        for (size_t j = 0; j < paramTypes.size(); j++)
            pieces.innames.push_back("p" + std::to_string(j));
        pieces.model = arch->defaultfp;

        try {
            fc->setPieces(pieces);
            applied++;
        } catch (const LowlevelError&) {}
    }
    if (applied > 0 && std::getenv("ENIGMA_DEBUG"))
        std::cerr << "[CallSite] " << fd->getName() << ": " << applied << " call-site types applied\n";
}

int main(int argc, char** argv) {
    std::string binary;
    std::string langId = "x86:LE:64:default";
    std::string outputFile;
    uint64_t baseAddr = 0x140001000;
    uint64_t entryPoint = 0;
    bool userSetLang = false, userSetBase = false, userSetEntry = false, showTiming = false;
    bool noCrt = false, noBridge = false, noTypeBridge = false, rawTypes = false;
    int64_t maxFuncs = 200;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-h") == 0) {
            printUsage(argv[0]);
            return 0;
        } else if (std::strcmp(argv[i], "-lang") == 0 && i + 1 < argc) {
            langId = argv[++i]; userSetLang = true;
        } else if (std::strcmp(argv[i], "-base") == 0 && i + 1 < argc) {
            baseAddr = std::stoull(argv[++i], nullptr, 16); userSetBase = true;
        } else if (std::strcmp(argv[i], "-entry") == 0 && i + 1 < argc) {
            entryPoint = std::stoull(argv[++i], nullptr, 16); userSetEntry = true;
        } else if ((std::strcmp(argv[i], "-o") == 0 || std::strcmp(argv[i], "-output") == 0) && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (std::strcmp(argv[i], "-time") == 0) {
            showTiming = true;
        } else if (std::strcmp(argv[i], "-max-func") == 0 && i + 1 < argc) {
            maxFuncs = std::stoll(argv[++i]);
            if (maxFuncs < 1) maxFuncs = 1;
        } else if (std::strcmp(argv[i], "-no-crt") == 0) {
            noCrt = true;
        } else if (std::strcmp(argv[i], "-no-bridge") == 0) {
            noBridge = true;
        } else if (std::strcmp(argv[i], "-no-type-bridge") == 0) {
            noTypeBridge = true;
        } else if (std::strcmp(argv[i], "-raw-types") == 0) {
            rawTypes = true;
        } else {
            binary = argv[i];
        }
    }

    if (binary.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    // Validate binary exists before proceeding and load raw bytes for string resolution
    std::vector<uint8_t> binaryData;
    {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(binary, ec)) {
            std::cerr << "Error: binary file not found: " << binary << "\n";
            return 1;
        }
        std::ifstream bf(binary, std::ios::binary);
        if (bf) {
            bf.seekg(0, std::ios::end);
            auto sz = bf.tellg();
            if (sz > 0) {
                binaryData.resize(static_cast<size_t>(sz));
                bf.seekg(0, std::ios::beg);
                bf.read(reinterpret_cast<char*>(binaryData.data()), sz);
            }
        }
    }

    // Auto-detect PE/ELF format via BinaryLoader
    bool isPE = false;
    auto bloader = ghidra::createLoader();
    std::map<uint64_t, std::string> symbolNames;
    uint64_t detectedBase = 0;
    uint64_t detectedEntry = 0;
    std::vector<ghidra::SectionInfo> peSections; // saved before bloader is moved
    if (bloader->load(binary)) {
        isPE = true;
        detectedBase = inferLoaderBase(*bloader);
        detectedEntry = bloader->getEntryPoint();
        if (!userSetLang) {
            std::string guessed = ghidra::BinaryLoader::guessLanguageFromArch(
                bloader->getArchitecture(), bloader->getBitness());
            if (guessed != "unknown") {
                // Use correct compiler spec
                std::string compiler = bloader->getFormatName() == "Mac OS X Mach-O"
                    ? "default"
                    : ghidra::BinaryLoader::guessCompilerSpecFromArch(
                        bloader->getArchitecture(), bloader->getBitness());
                // Append compiler part (5th colon-separated component)
                if (compiler != "default")
                    guessed = guessed + ":" + compiler;
                langId = guessed;
            }
        }
        if (!userSetBase) baseAddr = detectedBase;
        if (!userSetEntry) {
            if (userSetBase && detectedEntry >= detectedBase)
                entryPoint = baseAddr + (detectedEntry - detectedBase);
            else
                entryPoint = detectedEntry;
        }

        auto mapLoadedAddress = [&](uint64_t address) {
            if (userSetBase && address >= detectedBase)
                return baseAddr + (address - detectedBase);
            return address;
        };

        // Build symbol map from imports and exports.
        // For imports, also map the IAT entries' TARGET addresses (the actual
        // function VAs stored in the IAT) so that readonly propagation can
        // still resolve constant function pointers back to import names.
        {
            auto imps = bloader->getImports();
            if (std::getenv("ENIGMA_DEBUG"))
                std::cerr << "  Imports: " << imps.size() << "\n";
            for (const auto& imp : imps) {
                uint64_t mappedIatAddr = mapLoadedAddress(imp.address);
                symbolNames[mappedIatAddr] = imp.functionName;
                // Read the IAT entry value (actual function VA) from the binary
                auto iatBytes = bloader->getBytes(imp.address, 8);
                if (iatBytes.size() >= 8) {
                    uint64_t targetVa = 0;
                    for (int bi = 0; bi < 8; bi++)
                        targetVa |= static_cast<uint64_t>(iatBytes[bi]) << (bi * 8);
                    if (targetVa != 0)
                        symbolNames[mapLoadedAddress(targetVa)] = imp.functionName;
                }
            }
        }
        {
            auto exps = bloader->getExports();
            for (const auto& exp : exps)
                symbolNames[mapLoadedAddress(exp.address)] = exp.name;
            if (std::getenv("ENIGMA_DEBUG"))
                std::cerr << "  Exports: " << exps.size() << "\n";
        }
        {
            auto syms = bloader->getSymbols();
            for (const auto& sym : syms)
                if (!sym.name.empty() && sym.isFunction)
                    symbolNames[mapLoadedAddress(sym.address)] = sym.name;
            if (std::getenv("ENIGMA_DEBUG"))
                std::cerr << "  Symbols: " << syms.size() << ", mapped: ";
        }
        if (std::getenv("ENIGMA_DEBUG"))
            std::cerr << symbolNames.size() << "\n";

        // Save sections before bloader is moved into BinaryLoaderLoadImage
        peSections = bloader->getSections();
    }

    // Phase 1: Create ProgramDB and run the full analysis pipeline.
    // Phase 2 (after Architecture init): Bridge results into arch->symboltab.
    // The ProgramDB is kept alive until both Bridge phases complete.
    std::unique_ptr<ghidra::ProgramDB> analysisProgram;
    if (isPE) {
        try {
            auto* ramSpace = new ghidra::GenericAddressSpace("ram", 64,
                ghidra::AddressSpace::TYPE_RAM, 1);
            auto* constSpace = new ghidra::GenericAddressSpace("const", 64,
                ghidra::AddressSpace::TYPE_CONSTANT, 2);
            auto* uniqueSpace = new ghidra::GenericAddressSpace("unique", 64,
                ghidra::AddressSpace::TYPE_UNIQUE, 3);
            auto* regSpace = new ghidra::GenericAddressSpace("register", 64,
                ghidra::AddressSpace::TYPE_REGISTER, 4);
            auto* stackSpace = new ghidra::GenericAddressSpace("stack", 64,
                ghidra::AddressSpace::TYPE_STACK, 5);

            analysisProgram = std::make_unique<ghidra::ProgramDB>("analysis", nullptr, nullptr);
            auto* addrFactory = dynamic_cast<ghidra::ProgramAddressFactory*>(
                analysisProgram->getAddressFactory());
            if (addrFactory) {
                addrFactory->addAddressSpace(ramSpace);
                addrFactory->addAddressSpace(constSpace);
                addrFactory->addAddressSpace(uniqueSpace);
                addrFactory->addAddressSpace(regSpace);
                addrFactory->addAddressSpace(stackSpace);
                addrFactory->setDefaultSpace(ramSpace);
                addrFactory->setConstantSpace(ramSpace);
                addrFactory->setUniqueSpace(ramSpace);
                addrFactory->setRegisterSpace(ramSpace);
                addrFactory->setStackSpace(ramSpace);
            }

            if (bloader->populateProgram(analysisProgram.get())) {
                // Phase 1: Run full analysis pipeline + extract names into symbolNames
                ghidra::AnalysisBridge bridge(analysisProgram.get(), nullptr, symbolNames,
                    baseAddr, detectedBase, userSetBase);
                bridge.runAnalysis();
                bridge.enrichSymbolNames();
            }
        } catch (const std::exception& e) {
            if (std::getenv("ENIGMA_DEBUG"))
                std::cerr << "Analysis pipeline error: " << e.what() << "\n";
            analysisProgram.reset();
        }
    }

    if (!userSetEntry && entryPoint == 0)
        entryPoint = baseAddr;

    try {
        // Initialize decompiler library
        AttributeId::initialize();
        ElementId::initialize();
        CapabilityPoint::initializeAll();
        ArchitectureCapability::sortCapabilities();

        // Force PrintC translation unit to link (registers PrintCCapability via static init)
        volatile auto pcc = &PrintCCapability::printCCapability;
        (void)pcc;
        // Register SLEIGH specs
        std::string sleighDir = registerSleighSpecs();
        if (sleighDir.empty()) {
            std::cerr << "Error: No SLEIGH specs found. Set ENIGMA_SLEIGH_DIR or run from project root.\n";
            return 1;
        }

        if (std::getenv("ENIGMA_DEBUG")) {
            std::cerr << "SLEIGH dir: " << sleighDir << "\n";
            std::cerr << "Language: " << langId << "\n";
            std::cerr << "Binary: " << binary << "\n";
            std::cerr << "Base: 0x" << std::hex << baseAddr << std::dec << "\n";
            if (isPE)
                std::cerr << "Original base: 0x" << std::hex << detectedBase << std::dec << "\n";
            std::cerr << "Entry: 0x" << std::hex << entryPoint << std::dec << "\n";
            std::cerr << "Format: " << (isPE ? bloader->getFormatName() : "raw binary") << "\n";
        }

        // Loader is owned by Architecture via delete in ~Architecture() (architecture.cc:216).
        // Use unique_ptr until ownership transfers via .release().
        std::unique_ptr<LoadImage> loader;
        if (isPE) {
            loader = std::make_unique<BinaryLoaderLoadImage>(
                binary, std::move(bloader), detectedBase, baseAddr, userSetBase);
        } else {
            loader = std::make_unique<FileLoadImage>(binary, baseAddr);
        }

        // Create architecture - transfers loader ownership via .release()
        DocumentStorage store;
        auto arch = std::unique_ptr<SimpleBinaryArch>(
            new SimpleBinaryArch(binary, langId, &std::cerr, loader.release()));

        arch->init(store);

        // Enable read-only propagation: loads from read-only memory are replaced
        // with the constant value read from the binary. This eliminates many
        // unnecessary global variable references when reading from .rdata etc.
        arch->readonlypropagate = true;

        // Phase 2: Bridge analysis results into arch->symboltab.
        // Functions discovered by the analysis pipeline become FunctionSymbols,
        // code labels become LabSymbols, read-only memory ranges are marked.
        // Create TypeDatabase for import/export type bridging (lives for full decompile scope)
        std::unique_ptr<ghidra::TypeDatabase> typeDB;
        if (isPE)
            typeDB = ghidra::createWindowsTypeDatabase();

        if (analysisProgram && !noBridge) {
            ghidra::AnalysisBridge bridge(analysisProgram.get(), arch.get(), symbolNames,
                baseAddr, detectedBase, userSetBase);

            if (typeDB) bridge.setTypeDatabase(typeDB.get());

            bridge.bridgeFunctions();
            if (!noTypeBridge) bridge.bridgeTypes();
            try {
                bridge.bridgeImportSignatures();
            } catch (const std::exception& e) {
                if (std::getenv("ENIGMA_DEBUG"))
                    std::cerr << "bridgeImportSignatures error: " << e.what() << "\n";
            }
            try {
                bridge.bridgeNoReturnFlags();
            } catch (const std::exception& e) {
                if (std::getenv("ENIGMA_DEBUG"))
                    std::cerr << "bridgeNoReturnFlags error: " << e.what() << "\n";
            }
            bridge.bridgeLabels();
            bridge.bridgeReadOnlyRanges();
            analysisProgram.reset();
        } else if (isPE && !peSections.empty()) {
            // Fallback: mark read-only PE/ELF sections from saved section info
            AddrSpace* dataSpace = arch->getDefaultDataSpace();
            auto mapAddr = [&](uint64_t a) -> uint64_t {
                if (userSetBase && a >= detectedBase)
                    return baseAddr + (a - detectedBase);
                return a;
            };
            for (const auto& s : peSections) {
                if (s.isWritable || s.virtualSize == 0) continue;
                uint64_t start = mapAddr(s.virtualAddress);
                uint64_t endOff = start + std::max(s.virtualSize, s.fileSize) - 1;
                if (endOff <= start) continue;
                Range range(dataSpace, start, endOff);
                arch->symboltab->setPropertyRange(Varnode::readonly, range);
            }
        }
        // For non-PE raw binaries, mark read-only via the raw load image data.
        // This ensures readonlypropagate works for any binary format.
        if (!isPE) {
            AddrSpace* dataSpace = arch->getDefaultDataSpace();
            if (!binaryData.empty()) {
                Range range(dataSpace, baseAddr, baseAddr + binaryData.size() - 1);
                arch->symboltab->setPropertyRange(Varnode::readonly, range);
            }
        }

        // Calling convention models are created with isPrinted=false when set as default.
        // Enable printing so convention names appear in function declarations.
        for (auto& mp : arch->protoModels)
            mp.second->setPrintInDecl(true);
        if (arch->defaultfp)
            arch->defaultfp->setPrintInDecl(true);

        if (PrintC* pc = dynamic_cast<PrintC*>(arch->print)) {
            pc->setInplaceOps(true);
            pc->setBraceFormatFunction(Emit::next_line);
            
            // Set symbol provider to decouple identity from presentation
            pc->setSymbolProvider([&symbolNames](const Address& addr) {
                uint64_t off = addr.getOffset();
                auto it = symbolNames.find(off);
                return (it != symbolNames.end()) ? it->second : std::string("");
            });
        }

        AddrSpace* codeSpace = arch->getDefaultCodeSpace();
        if (!codeSpace) {
            std::cerr << "Error: No default code space.\n";
            return 1;
        }

        // Pre-register remaining known function symbols into arch->symboltab.
        // AnalysisBridge already registered analyzer-discovered functions.
        // This handles any names that were added outside the bridge (imports,
        // exports, raw-binary ELF loader symbols, etc.).
        {
            int already = 0, added = 0;
            for (const auto& pair : symbolNames) {
                if (pair.first == 0 || pair.second.empty()) continue;
                Address knownAddr(codeSpace, static_cast<int8>(pair.first));
                if (arch->symboltab->getGlobalScope()->queryFunction(knownAddr)) {
                    already++;
                    continue;
                }
                try {
                    arch->symboltab->getGlobalScope()->addFunction(knownAddr, pair.second);
                    added++;
                } catch (const ghidra_decompiler::DuplicateFunctionError&) {
                    already++;
                }
            }
            if (std::getenv("ENIGMA_DEBUG")) {
                std::cerr << "Pre-registered " << added << " new + " << already
                          << " existing = " << symbolNames.size() << " total symbols\n";
            }
        }

        // Register known library function prototypes for better type inference.
        // This tells the decompiler the exact parameter types for common CRT functions,
        // enabling string resolution, correct argument types, and better overall output.
        {
            struct LibFuncSig {
                const char* name;
                const char* retType;
                std::vector<const char*> paramTypes;
                bool varargs;
            };
            static const LibFuncSig libFuncs[] = {
                // === C standard library ===
                {"printf", "int", {"char *"}, true},
                {"fprintf", "int", {"void *", "char *"}, true},
                {"sprintf", "int", {"char *", "char *"}, true},
                {"snprintf", "int", {"char *", "size_t", "char *"}, true},
                {"puts", "int", {"char *"}, false},
                {"scanf", "int", {"char *"}, true},
                // === MinGW printf/scanf family ===
                {"__mingw_printf", "int", {"char *"}, true},
                {"__mingw_fprintf", "int", {"void *", "char *"}, true},
                {"__mingw_sprintf", "int", {"char *", "char *"}, true},
                {"__mingw_snprintf", "int", {"char *", "size_t", "char *"}, true},
                {"__mingw_vfprintf", "int", {"void *", "char *", "char *"}, false},
                {"__mingw_vsprintf", "int", {"char *", "char *", "char *"}, false},
                {"__mingw_vsnprintf", "int", {"char *", "size_t", "char *", "char *"}, false},
                {"__mingw_scanf", "int", {"char *"}, true},
                {"__mingw_fscanf", "int", {"void *", "char *"}, true},
                {"__mingw_sscanf", "int", {"char *", "char *"}, true},
                {"sscanf", "int", {"char *", "char *"}, true},
                {"fscanf", "int", {"void *", "char *"}, true},
                {"memcpy", "void *", {"void *", "void *", "size_t"}, false},
                {"memmove", "void *", {"void *", "void *", "size_t"}, false},
                {"memset", "void *", {"void *", "int", "size_t"}, false},
                {"memcmp", "int", {"void *", "void *", "size_t"}, false},
                {"memchr", "void *", {"void *", "int", "size_t"}, false},
                {"strlen", "size_t", {"char *"}, false},
                {"strnlen", "size_t", {"char *", "size_t"}, false},
                {"strcpy", "char *", {"char *", "char *"}, false},
                {"strncpy", "char *", {"char *", "char *", "size_t"}, false},
                {"strcat", "char *", {"char *", "char *"}, false},
                {"strncat", "char *", {"char *", "char *", "size_t"}, false},
                {"strcmp", "int", {"char *", "char *"}, false},
                {"strncmp", "int", {"char *", "char *", "size_t"}, false},
                {"strchr", "char *", {"char *", "int"}, false},
                {"strrchr", "char *", {"char *", "int"}, false},
                {"strstr", "char *", {"char *", "char *"}, false},
                {"strspn", "size_t", {"char *", "char *"}, false},
                {"strcspn", "size_t", {"char *", "char *"}, false},
                {"strtok", "char *", {"char *", "char *"}, false},
                {"strerror", "char *", {"int"}, false},
                {"wcslen", "size_t", {"wchar_t *"}, false},
                {"wcscpy", "wchar_t *", {"wchar_t *", "wchar_t *"}, false},
                {"wcscmp", "int", {"wchar_t *", "wchar_t *"}, false},
                {"malloc", "void *", {"size_t"}, false},
                {"calloc", "void *", {"size_t", "size_t"}, false},
                {"realloc", "void *", {"void *", "size_t"}, false},
                {"free", "void", {"void *"}, false},
                {"exit", "void", {"int"}, false},
                {"abort", "void", {}, false},
                {"atexit", "int", {"void *"}, false},
                {"qsort", "void", {"void *", "size_t", "size_t", "void *"}, false},
                {"bsearch", "void *", {"void *", "void *", "size_t", "size_t", "void *"}, false},
                {"abs", "int", {"int"}, false},
                {"labs", "long", {"long"}, false},
                {"rand", "int", {}, false},
                {"srand", "void", {"unsigned"}, false},
                {"atof", "double", {"char *"}, false},
                {"atoi", "int", {"char *"}, false},
                {"atol", "long", {"char *"}, false},
                {"strtol", "long", {"char *", "char *", "int"}, false},
                {"strtoul", "ULONG", {"char *", "char *", "int"}, false},
                {"strtoll", "int64", {"char *", "char *", "int"}, false},
                {"strtoull", "uint64", {"char *", "char *", "int"}, false},
                {"fopen", "void *", {"char *", "char *"}, false},
                {"fclose", "int", {"void *"}, false},
                {"fread", "size_t", {"void *", "size_t", "size_t", "void *"}, false},
                {"fwrite", "size_t", {"void *", "size_t", "size_t", "void *"}, false},
                {"fflush", "int", {"void *"}, false},
                {"fseek", "int", {"void *", "long", "int"}, false},
                {"ftell", "long", {"void *"}, false},
                {"rewind", "void", {"void *"}, false},
                {"ferror", "int", {"void *"}, false},
                {"feof", "int", {"void *"}, false},
                {"remove", "int", {"char *"}, false},
                {"rename", "int", {"char *", "char *"}, false},
                {"tmpfile", "void *", {}, false},
                {"setvbuf", "int", {"void *", "char *", "int", "size_t"}, false},
                {"perror", "void", {"char *"}, false},
                {"time", "size_t", {"void *"}, false},
                {"clock", "size_t", {}, false},
                {"difftime", "double", {"size_t", "size_t"}, false},
                {"gmtime", "void *", {"void *"}, false},
                {"localtime", "void *", {"void *"}, false},
                {"mktime", "size_t", {"void *"}, false},
                {"asctime", "char *", {"void *"}, false},
                {"ctime", "char *", {"void *"}, false},
                {"strftime", "size_t", {"char *", "size_t", "char *", "void *"}, false},
                {"isalnum", "int", {"int"}, false},
                {"isalpha", "int", {"int"}, false},
                {"iscntrl", "int", {"int"}, false},
                {"isdigit", "int", {"int"}, false},
                {"isgraph", "int", {"int"}, false},
                {"islower", "int", {"int"}, false},
                {"isprint", "int", {"int"}, false},
                {"ispunct", "int", {"int"}, false},
                {"isspace", "int", {"int"}, false},
                {"isupper", "int", {"int"}, false},
                {"isxdigit", "int", {"int"}, false},
                {"tolower", "int", {"int"}, false},
                {"toupper", "int", {"int"}, false},
                {"setlocale", "char *", {"int", "char *"}, false},
                // === Math library ===
                {"sin", "double", {"double"}, false},
                {"cos", "double", {"double"}, false},
                {"tan", "double", {"double"}, false},
                {"asin", "double", {"double"}, false},
                {"acos", "double", {"double"}, false},
                {"atan", "double", {"double"}, false},
                {"atan2", "double", {"double", "double"}, false},
                {"sinh", "double", {"double"}, false},
                {"cosh", "double", {"double"}, false},
                {"tanh", "double", {"double"}, false},
                {"exp", "double", {"double"}, false},
                {"log", "double", {"double"}, false},
                {"log10", "double", {"double"}, false},
                {"pow", "double", {"double", "double"}, false},
                {"sqrt", "double", {"double"}, false},
                {"ceil", "double", {"double"}, false},
                {"floor", "double", {"double"}, false},
                {"fabs", "double", {"double"}, false},
                {"modf", "double", {"double", "double *"}, false},
                {"frexp", "double", {"double", "int *"}, false},
                {"ldexp", "double", {"double", "int"}, false},
                // === Windows CRT (internal) ===
                {"_amsg_exit", "void", {"int"}, false},
                {"_exit", "void", {"int"}, false},
                {"_initterm", "void", {"void *", "void *"}, false},
                {"_initterm_e", "int", {"void *", "void *"}, false},
                {"_set_app_type", "void", {"int"}, false},
                {"_configure_narrow_argv", "void", {"int"}, false},
                {"_configure_wide_argv", "void", {"int"}, false},
                {"_initialize_onexit_table", "int", {"void *"}, false},
                {"_register_onexit_function", "int", {"void *", "void *"}, false},
                {"_crt_atexit", "int", {"void *"}, false},
                {"_crtTerminateProcess", "void", {}, false},
                {"_seh_filter_exe", "int", {"void *", "void *"}, false},
                {"_set_fmode", "int", {"int"}, false},
                {"_get_initial_narrow_environment", "char *", {}, false},
                {"_initialize_narrow_argv", "int", {}, false},
                {"_initialize_wide_argv", "int", {}, false},
                {"_set_new_mode", "int", {"int"}, false},
                {"_set_error_mode", "int", {"int"}, false},
                {"_assert", "void", {"void *", "void *", "unsigned"}, false},
                {"_wassert", "void", {"wchar_t *", "wchar_t *", "unsigned"}, false},
                {"_beginthread", "uint8", {"void *", "unsigned", "void *"}, false},
                {"_endthread", "void", {}, false},
                {"_beginthreadex", "uint8", {"void *", "unsigned", "void *", "void *", "unsigned", "unsigned *"}, false},
                {"_endthreadex", "void", {"unsigned"}, false},
                // === Kernel32 / Windows API ===
                {"Sleep", "void", {"DWORD"}, false},
                {"SleepEx", "DWORD", {"DWORD", "BOOL"}, false},
                {"SetUnhandledExceptionFilter", "void *", {"void *"}, false},
                {"UnhandledExceptionFilter", "LONG", {"void *"}, false},
                {"GetLastError", "DWORD", {}, false},
                {"SetLastError", "void", {"DWORD"}, false},
                {"VirtualProtect", "BOOL", {"LPVOID", "SIZE_T", "DWORD", "PDWORD"}, false},
                {"VirtualQuery", "SIZE_T", {"LPCVOID", "void *", "SIZE_T"}, false},
                {"VirtualAlloc", "LPVOID", {"LPVOID", "SIZE_T", "DWORD", "DWORD"}, false},
                {"VirtualFree", "BOOL", {"LPVOID", "SIZE_T", "DWORD"}, false},
                {"HeapAlloc", "LPVOID", {"HANDLE", "DWORD", "SIZE_T"}, false},
                {"HeapFree", "BOOL", {"HANDLE", "DWORD", "LPVOID"}, false},
                {"HeapReAlloc", "LPVOID", {"HANDLE", "DWORD", "LPVOID", "SIZE_T"}, false},
                {"HeapSize", "SIZE_T", {"HANDLE", "DWORD", "LPCVOID"}, false},
                {"GetProcessHeap", "HANDLE", {}, false},
                {"GetProcessHeaps", "DWORD", {"DWORD", "HANDLE *"}, false},
                {"InitializeCriticalSection", "void", {"void *"}, false},
                {"InitializeCriticalSectionAndSpinCount", "BOOL", {"void *", "DWORD"}, false},
                {"EnterCriticalSection", "void", {"void *"}, false},
                {"TryEnterCriticalSection", "BOOL", {"void *"}, false},
                {"LeaveCriticalSection", "void", {"void *"}, false},
                {"DeleteCriticalSection", "void", {"void *"}, false},
                {"CreateThread", "HANDLE", {"void *", "SIZE_T", "void *", "LPVOID", "DWORD", "LPDWORD"}, false},
                {"CreateRemoteThread", "HANDLE", {"HANDLE", "void *", "SIZE_T", "void *", "LPVOID", "DWORD", "LPDWORD"}, false},
                {"WaitForSingleObject", "DWORD", {"HANDLE", "DWORD"}, false},
                {"WaitForMultipleObjects", "DWORD", {"DWORD", "HANDLE *", "BOOL", "DWORD"}, false},
                {"CloseHandle", "BOOL", {"HANDLE"}, false},
                {"GetModuleHandleA", "HMODULE", {"LPCSTR"}, false},
                {"GetModuleHandleW", "HMODULE", {"LPCWSTR"}, false},
                {"GetModuleHandleExA", "BOOL", {"DWORD", "LPCSTR", "HMODULE *"}, false},
                {"GetModuleHandleExW", "BOOL", {"DWORD", "LPCWSTR", "HMODULE *"}, false},
                {"GetProcAddress", "void *", {"HMODULE", "LPCSTR"}, false},
                {"LoadLibraryA", "HMODULE", {"LPCSTR"}, false},
                {"LoadLibraryW", "HMODULE", {"LPCWSTR"}, false},
                {"LoadLibraryExA", "HMODULE", {"LPCSTR", "HANDLE", "DWORD"}, false},
                {"FreeLibrary", "BOOL", {"HMODULE"}, false},
                {"GetStdHandle", "HANDLE", {"DWORD"}, false},
                {"WriteFile", "BOOL", {"HANDLE", "LPCVOID", "DWORD", "LPDWORD", "void *"}, false},
                {"ReadFile", "BOOL", {"HANDLE", "LPVOID", "DWORD", "LPDWORD", "void *"}, false},
                {"TerminateProcess", "BOOL", {"HANDLE", "UINT"}, false},
                {"GetCurrentProcess", "HANDLE", {}, false},
                {"GetCurrentThread", "HANDLE", {}, false},
                {"GetCurrentThreadId", "DWORD", {}, false},
                {"GetCurrentProcessId", "DWORD", {}, false},
                {"GetSystemTimeAsFileTime", "void", {"void *"}, false},
                {"QueryPerformanceCounter", "BOOL", {"int64 *"}, false},
                {"QueryPerformanceFrequency", "BOOL", {"int64 *"}, false},
                {"IsProcessorFeaturePresent", "BOOL", {"DWORD"}, false},
                {"EncodePointer", "PVOID", {"PVOID"}, false},
                {"DecodePointer", "PVOID", {"PVOID"}, false},
                {"EncodeSystemPointer", "PVOID", {"PVOID"}, false},
                {"DecodeSystemPointer", "PVOID", {"PVOID"}, false},
                {"FlushInstructionCache", "BOOL", {"HANDLE", "LPCVOID", "SIZE_T"}, false},
                {"FlushProcessWriteBuffers", "void", {}, false},
                {"RaiseException", "void", {"DWORD", "DWORD", "DWORD", "void *"}, false},
                {"SetUnhandledExceptionFilter", "void *", {"void *"}, false},
                {"UnhandledExceptionFilter", "LONG", {"void *"}, false},
                {"GetStartupInfoA", "void", {"void *"}, false},
                {"GetCommandLineA", "LPSTR", {}, false},
                {"GetCommandLineW", "LPWSTR", {}, false},
                {"GetEnvironmentStringsA", "LPSTR", {}, false},
                {"GetEnvironmentStringsW", "LPWSTR", {}, false},
                {"FreeEnvironmentStringsA", "BOOL", {"LPSTR"}, false},
                {"FreeEnvironmentStringsW", "BOOL", {"LPWSTR"}, false},
                {"SetEnvironmentVariableA", "BOOL", {"LPCSTR", "LPCSTR"}, false},
                {"SetEnvironmentVariableW", "BOOL", {"LPCWSTR", "LPCWSTR"}, false},
                {"GetEnvironmentVariableA", "DWORD", {"LPCSTR", "LPSTR", "DWORD"}, false},
                {"GetEnvironmentVariableW", "DWORD", {"LPCWSTR", "LPWSTR", "DWORD"}, false},
                {"SetStdHandle", "BOOL", {"DWORD", "HANDLE"}, false},
                {"GetFileType", "DWORD", {"HANDLE"}, false},
                {"SetHandleInformation", "BOOL", {"HANDLE", "DWORD", "DWORD"}, false},
                {"GetSystemInfo", "void", {"void *"}, false},
                {"GetNativeSystemInfo", "void", {"void *"}, false},
                {"InitializeSListHead", "void", {"void *"}, false},
                {"InterlockedFlushSList", "void *", {"void *"}, false},
                {"QueryDepthSList", "WORD", {"void *"}, false},
                // === Additional CRT (Windows-specific) ===
                {"_configthreadlocale", "int", {"int"}, false},
                {"_open", "int", {"char *", "int", "int"}, false},
                {"_sopen_s", "int", {"int *", "char *", "int", "int", "int"}, false},
                {"_close", "int", {"int"}, false},
                {"_read", "int", {"int", "void *", "unsigned"}, false},
                {"_write", "int", {"int", "void *", "unsigned"}, false},
                {"_lseek", "long", {"int", "long", "int"}, false},
                {"_tell", "long", {"int"}, false},
                {"_commit", "int", {"int"}, false},
                {"_dup", "int", {"int"}, false},
                {"_dup2", "int", {"int", "int"}, false},
                {"_pipe", "int", {"int *", "unsigned", "int"}, false},
                {"_chmod", "int", {"char *", "int"}, false},
                {"_chsize_s", "int", {"int", "int64"}, false},
                {"_filelength", "long", {"int"}, false},
                {"_filelengthi64", "int64", {"int"}, false},
                {"_fstat32", "int", {"int", "void *"}, false},
                {"_fstat64", "int", {"int", "void *"}, false},
                {"_stat32", "int", {"char *", "void *"}, false},
                {"_stat64", "int", {"char *", "void *"}, false},
                {"_access", "int", {"char *", "int"}, false},
                {"_mkdir", "int", {"char *"}, false},
                {"_rmdir", "int", {"char *"}, false},
                {"_unlink", "int", {"char *"}, false},
                {"_tempnam", "char *", {"char *", "char *"}, false},
                {"_tempnam_s", "int", {"char *", "size_t", "char *", "char *"}, false},
                {"_getcwd", "char *", {"char *", "int"}, false},
                {"_chdir", "int", {"char *"}, false},
                {"_splitpath", "void", {"char *", "char *", "char *", "char *", "char *"}, false},
                {"_splitpath_s", "int", {"char *", "char *", "size_t", "char *", "size_t", "char *", "size_t", "char *", "size_t"}, false},
                {"_makepath", "void", {"char *", "char *", "char *", "char *", "char *"}, false},
                {"_makepath_s", "int", {"char *", "size_t", "char *", "char *", "char *", "char *"}, false},
                {"_wsplitpath_s", "int", {"wchar_t *", "wchar_t *", "size_t", "wchar_t *", "size_t", "wchar_t *", "size_t", "wchar_t *", "size_t"}, false},
                {"_wmakepath_s", "int", {"wchar_t *", "size_t", "wchar_t *", "wchar_t *", "wchar_t *", "wchar_t *"}, false},
                {"_dupenv_s", "int", {"char *", "size_t", "char *", "size_t"}, false},
                {"_wdupenv_s", "int", {"wchar_t *", "size_t", "wchar_t *", "size_t"}, false},
                {"_strdup", "char *", {"char *"}, false},
                {"_strdup_s", "int", {"char *", "size_t", "char *"}, false},
                {"_wcsdup", "wchar_t *", {"wchar_t *"}, false},
                {"_wcsdup_s", "int", {"wchar_t *", "size_t", "wchar_t *"}, false},
                {"_itoa_s", "int", {"int", "char *", "size_t", "int"}, false},
                {"_itow_s", "int", {"int", "wchar_t *", "size_t", "int"}, false},
                // === Memory management (Windows) ===
                {"LocalAlloc", "void *", {"UINT", "SIZE_T"}, false},
                {"LocalFree", "void *", {"void *"}, false},
                {"GlobalAlloc", "void *", {"UINT", "SIZE_T"}, false},
                {"GlobalFree", "void *", {"void *"}, false},
            };
            int4 ptrSize = arch->types->getSizeOfPointer();
            int4 wordSize = arch->getDefaultDataSpace()->getWordSize();
            std::function<Datatype*(const std::string&)> getTypeByName;
            getTypeByName = [&](const std::string& tn) -> Datatype* {
                // Try bridged types first — these come from the DataTypeManager bridge
                // and include named types like DWORD, HANDLE, LPVOID, etc.
                {
                    Datatype* bridged = arch->types->findByName(tn);
                    if (bridged) return bridged;
                }
                if (tn == "void") return arch->types->getTypeVoid();
                if (tn == "bool") return arch->types->getBase(1, TYPE_BOOL);
                if (tn == "char") return arch->types->getBase(1, TYPE_INT);
                if (tn == "short") return arch->types->getBase(2, TYPE_INT);
                if (tn == "ushort" || tn == "unsigned short" || tn == "WORD") return arch->types->getBase(2, TYPE_UINT);
                if (tn == "int" || tn == "int4" || tn == "BOOL" || tn == "LONG" || tn == "DWORD" || tn == "UINT" || tn == "unsigned" || tn == "unsigned int") return arch->types->getBase(4, TYPE_INT);
                if (tn == "uint" || tn == "uint4" || tn == "ULONG" || tn == "DWORD32") return arch->types->getBase(4, TYPE_UINT);
                if (tn == "int8" || tn == "int64" || tn == "LONGLONG") return arch->types->getBase(8, TYPE_INT);
                if (tn == "uint8" || tn == "uint64" || tn == "ULONGLONG" || tn == "DWORD64" || tn == "size_t" || tn == "SIZE_T" || tn == "DWORD_PTR") return arch->types->getBase(8, TYPE_UINT);
                if (tn == "float") return arch->types->getBase(4, TYPE_FLOAT);
                if (tn == "double") return arch->types->getBase(8, TYPE_FLOAT);
                if (tn == "wchar_t" || tn == "WCHAR") return arch->types->getBase(2, TYPE_INT);
                // Pointer types: "type *"
                if (tn.size() >= 2 && tn.rfind(" *", tn.size()) != std::string::npos &&
                    tn.rfind(" *", tn.size()) == tn.size() - 2) {
                    std::string baseName = tn.substr(0, tn.size() - 2);
                    Datatype* base = getTypeByName(baseName);
                    if (base) return arch->types->getTypePointer(ptrSize, base, wordSize);
                    return arch->types->getTypePointer(ptrSize, arch->types->getBase(1, TYPE_INT), wordSize);
                }
                // Common Windows pointer typedefs
                if (tn == "HANDLE" || tn == "HMODULE" || tn == "HINSTANCE" || tn == "HWND" || tn == "PVOID" || tn == "LPVOID" || tn == "LPCVOID")
                    return arch->types->getTypePointer(ptrSize, arch->types->getTypeVoid(), wordSize);
                if (tn == "LPCSTR" || tn == "LPSTR" || tn == "PCSTR" || tn == "PSTR")
                    return arch->types->getTypePointer(ptrSize, arch->types->getBase(1, TYPE_INT), wordSize);
                if (tn == "LPCWSTR" || tn == "LPWSTR" || tn == "PCWSTR" || tn == "PWSTR")
                    return arch->types->getTypePointer(ptrSize, arch->types->getBase(2, TYPE_INT), wordSize);
                // LPDWORD = unsigned int *
                if (tn == "LPDWORD" || tn == "PDWORD" || tn == "PUINT")
                    return arch->types->getTypePointer(ptrSize, arch->types->getBase(4, TYPE_UINT), wordSize);
                return nullptr;
            };
            for (const auto& lib : libFuncs) {
                for (const auto& pair : symbolNames) {
                    if (pair.second != lib.name) continue;
                    if (pair.first == 0) continue;
                    Address faddr(codeSpace, static_cast<int8>(pair.first));
                    Funcdata* fd = arch->symboltab->getGlobalScope()->queryFunction(faddr);
                    if (!fd) continue;
                    PrototypePieces pp;
                    pp.model = arch->defaultfp;
                    pp.outtype = getTypeByName(lib.retType);
                    if (!pp.outtype) pp.outtype = arch->types->getTypeVoid();
                    for (const auto& pt : lib.paramTypes) {
                        Datatype* dt = getTypeByName(pt);
                        if (dt) {
                            pp.intypes.push_back(dt);
                            pp.innames.push_back("");
                        }
                    }
                    pp.firstVarArgSlot = lib.varargs ? static_cast<int4>(pp.intypes.size()) : -1;
                    fd->getFuncProto().setPieces(pp);
                    if (std::getenv("ENIGMA_DEBUG"))
                        std::cerr << "  proto " << lib.name << "(" << pp.intypes.size()
                                  << " params, varargs=" << lib.varargs << ")\n";
                }
            }
        }

        // Check if entry point already has a function symbol from pre-registration
        Address entryAddr(codeSpace, static_cast<int8>(entryPoint));
        Funcdata* fdEntry = arch->symboltab->getGlobalScope()->queryFunction(entryAddr);
        if (!fdEntry) {
            std::string entryName;
            auto entryIt = symbolNames.find(entryPoint);
            if (entryIt != symbolNames.end()) entryName = entryIt->second;
            if (entryName.empty()) entryName = "entry";
            FunctionSymbol* fsym = arch->symboltab->getGlobalScope()->addFunction(entryAddr, entryName);
            if (!fsym) {
                std::cerr << "Error: Could not create function symbol at entry point.\n";
                return 1;
            }
            fdEntry = fsym->getFunction();
        }

        if (!fdEntry) {
            std::cerr << "Error: No function data at entry point.\n";
            return 1;
        }

        auto t0 = std::chrono::high_resolution_clock::now();
        // For small raw binaries, limit flow analysis to the binary's byte count
        // to prevent walking through zero-padding ("Flow exceeded maximum allowable instructions").
        // For small raw binaries, limit the flow analysis range to prevent
        // walking through zero-padding past the end of the file
        // ("Flow exceeded maximum allowable instructions").
        if (!isPE) {
            std::error_code ec;
            auto fsize = std::filesystem::file_size(binary, ec);
            if (!ec && fsize > 0 && fsize < 100000) {
                Address fb(codeSpace, static_cast<int8>(baseAddr));
                Address fe(codeSpace, static_cast<int8>(baseAddr + fsize));
                fdEntry->followFlow(fb, fe);
            }
        }
        arch->allacts.getCurrent()->perform(*fdEntry);
        if (typeDB) applyTypeDatabaseToCallSpecs(fdEntry, typeDB.get(), arch->types, arch.get());
        auto t1 = std::chrono::high_resolution_clock::now();

        if (std::getenv("ENIGMA_DEBUG"))
            std::cerr << "Entry done, calls: " << fdEntry->numCalls() << "\n";

        // Known CRT/library function name prefixes — not user code; skip following.
        // Covers both MinGW/GCC CRT and MSVC/Windows CRT naming conventions.
        static const std::unordered_set<std::string> crtPrefixes = {
            // === MinGW/GCC CRT ===
            "__mingw_", "__do_global_", "__gcc_", "_Unwind_",
            "__main", "__security_", "_pei386_", "__cpu_features_",
            "__chkstk", "__alloca", "__libc_start_main",
            "__getmainargs", "__p__", "__set_app_type",
            "__huge_val", "__dmath_", "__signbit",
            "_GCC_specific_handler",
            // === MSVC/Windows CRT entry and init ===
            "mainCRTStartup", "wmainCRTStartup", "WinMainCRTStartup",
            "__tmainCRTStartup", "_tmainCRTStartup",
            "__scrt_", "__vcrt_",
            // === Exception handling (MSVC/GCC) ===
            "_except_handler", "_C_specific_handler", "_NLG_",
            // === CRT init helpers ===
            "_configure_", "_initialize_", "_register_",
            "_callnewh", "_execute_onexit_table", "_register_onexit_function",
        };
        static const std::unordered_set<std::string> crtExact = {
            "_init", "_fini", "__main",
        };
        auto isCrtFunction = [&](const std::string& name) -> bool {
            if (name.empty()) return false;
            if (crtExact.count(name)) return true;
            for (const auto& p : crtPrefixes)
                if (name.find(p) == 0) return true;
            // HEURISTIC: In PE/ELF binaries, names starting with '_' are reserved
            // for the C/C++ implementation (CRT internals, compiler helpers).
            // Real user code almost never uses a leading underscore.
            if (!noCrt && isPE && name[0] == '_') return true;
            return false;
            (void)noCrt;
        };

        // Follow call graph to decompile reachable functions.
        // CRT/library functions are decompiled for callee discovery but not
        // added to the output (unless they have an import/export name) and
        // don't count toward maxFuncs. Their non-CRT callees ARE discovered
        // and followed normally (one level deep through CRT).
        std::vector<Funcdata*> allFds;
        std::vector<Funcdata*> queue = {fdEntry};
        std::set<uint64_t> visited = {entryPoint};
        std::set<uint64_t> outputSeen;
        std::set<uint64_t> thunkAddrs;   // Detected import thunks
        std::set<uint64_t> bfsMainCandidates;  // Non-CRT callees from CRT functions (candidate main, BFS tracking)
        int64_t userFuncCount = 0;

        // Helper: check if an address falls within an executable PE section.
        // Prevents creating decompiler functions at non-executable addresses
        // (e.g. IAT entries in .idata) which would produce garbage instructions.
        // Uses a sorted vector + binary search for O(log N) lookup per address.
        struct SectionRange { uint64_t start; uint64_t end; bool isExec; };
        std::vector<SectionRange> sortedSections;
        sortedSections.reserve(peSections.size());
        for (const auto& sect : peSections) {
            sortedSections.push_back({sect.virtualAddress,
                                      sect.virtualAddress + sect.virtualSize,
                                      sect.isExecutable});
        }
        std::sort(sortedSections.begin(), sortedSections.end(),
                  [](const SectionRange& a, const SectionRange& b) { return a.start < b.start; });
        auto isExecutableAddress = [&](uint64_t addr) -> bool {
            if (sortedSections.empty()) return true; // no section info — allow (raw binary)
            // Binary search: find first section whose start > addr
            auto it = std::upper_bound(sortedSections.begin(), sortedSections.end(), addr,
                [](uint64_t val, const SectionRange& s) { return val < s.start; });
            if (it == sortedSections.begin()) return false; // addr < first section — reject
            --it;
            if (addr < it->end) return it->isExec;
            return false; // addr not in any section — reject
        };
        // CRT discovery queue: enables multi-level tracing through CRT startup chain
        // (e.g., entry → mainCRTStartup → __tmainCRTStartup → ... → main).
        // Behavioral CRT classification runs in a post-BFS pass (see below).

        auto createOrLookup = [&](const Address& addr, const std::string& hint,
                                   uint64_t offsetHint) -> Funcdata* {
            if (addr.isInvalid()) return nullptr;
            Funcdata* fd = arch->symboltab->getGlobalScope()->queryFunction(addr);
            if (fd) return fd;
            std::string name;
            auto it = symbolNames.find(offsetHint);
            if (it != symbolNames.end()) name = it->second;
            if (name.empty()) name = hint;
            if (name.empty()) {
                std::ostringstream oss;
                oss << "sub_0x" << std::hex << offsetHint;
                name = oss.str();
            }
            FunctionSymbol* sym = arch->symboltab->getGlobalScope()->addFunction(addr, name);
            return sym ? sym->getFunction() : nullptr;
        };

        auto rememberOutput = [&](Funcdata* f) {
            if (!f) return;
            uint64_t off = f->getAddress().getOffset();
            if (outputSeen.insert(off).second)
                allFds.push_back(f);
        };

        auto decompileOne = [&](Funcdata* fd) -> bool {
            if (!fd || fd->isProcStarted()) return false;
            arch->clearAnalysis(fd);
            arch->allacts.getCurrent()->reset(*fd);
            try {
                auto t0 = std::chrono::high_resolution_clock::now();
                arch->allacts.getCurrent()->perform(*fd);
                if (typeDB) applyTypeDatabaseToCallSpecs(fd, typeDB.get(), arch->types, arch.get());
                if (showTiming) {
                    auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::high_resolution_clock::now() - t0).count();
                    std::cerr << "  callee 0x" << std::hex << fd->getAddress().getOffset()
                              << std::dec << ": " << dt << "ms\n";
                }
            } catch (const LowlevelError&) { return false; }
            return fd->isProcStarted();
        };

        auto addNonCrtCalleesToQueue = [&](Funcdata* fd) {
            for (int4 j = 0; j < fd->numCalls(); ++j) {
                FuncCallSpecs* fc2 = fd->getCallSpecs(j);
                const Address& ca2 = fc2->getEntryAddress();
                if (ca2.isInvalid() || ca2.getSpace() != codeSpace) continue;
                uint64_t off2 = ca2.getOffset();
                if (visited.count(off2)) continue;
                visited.insert(off2);
                Funcdata* fd2 = fc2->getFuncdata();
                if (!fd2 && off2 >= baseAddr && isExecutableAddress(off2))
                    fd2 = createOrLookup(ca2, fc2->getName(), off2);
                if (!fd2) continue;
                if (!isExecutableAddress(off2)) continue;
                if (fd2->isProcStarted()) {
                    if (!isCrtFunction(fd2->getName()))
                        rememberOutput(fd2);
                    continue;
                }
                if (!isCrtFunction(fc2->getName())) {
                    if (decompileOne(fd2)) {
                        rememberOutput(fd2);
                        userFuncCount++;
                        queue.push_back(fd2);
                    }
                }
            }
        };

        rememberOutput(fdEntry);
        userFuncCount = 1;

        while (!queue.empty() && !(maxFuncs > 0 && userFuncCount >= maxFuncs)) {
            Funcdata* cur = queue.back();
            queue.pop_back();

            for (int4 i = 0; i < cur->numCalls(); ++i) {
                FuncCallSpecs* fc = cur->getCallSpecs(i);
                const Address& calleeAddr = fc->getEntryAddress();
                if (calleeAddr.isInvalid() || calleeAddr.getSpace() != codeSpace) continue;

                uint64_t calleeOff = calleeAddr.getOffset();
                if (visited.count(calleeOff)) continue;
                visited.insert(calleeOff);

                if (std::getenv("ENIGMA_DEBUG"))
                    std::cerr << "  call " << i << ": 0x" << std::hex << calleeOff << std::dec
                              << " " << fc->getName() << "\n";

                Funcdata* calleeFd = fc->getFuncdata();
                if (!calleeFd && calleeOff >= baseAddr && isExecutableAddress(calleeOff))
                    calleeFd = createOrLookup(calleeAddr, fc->getName(), calleeOff);

                if (!calleeFd) {
                    if (std::getenv("ENIGMA_DEBUG"))
                        std::cerr << "    -> no Funcdata (external/import)\n";
                    continue;
                }

                // Skip functions in non-executable sections (e.g. IAT entries in .idata)
                // These produce garbage instructions and halt_baddata when decompiled.
                if (!isExecutableAddress(calleeOff)) {
                    if (std::getenv("ENIGMA_DEBUG"))
                        std::cerr << "    -> skipped non-executable section\n";
                    continue;
                }

                if (calleeFd->isProcStarted()) {
                    if (!isCrtFunction(calleeFd->getName()))
                        rememberOutput(calleeFd);
                    continue;
                }

                if (!decompileOne(calleeFd)) continue;

                // Detect import thunks: auto-named functions that pass through to a known import
                {
                    std::string fname = calleeFd->getName();
                    uint64_t off = calleeFd->getAddress().getOffset();
                    bool autoName = (fname.rfind("sub_0x", 0) == 0 || fname.rfind("function_0x", 0) == 0);
                    bool isThunk = false;
                    if (autoName && symbolNames.find(off) == symbolNames.end() && isExecutableAddress(off)) {
                        int nCallOps = 0;
                        uint64_t importTarget = 0;
                        for (auto it = calleeFd->beginOpAll(); it != calleeFd->endOpAll(); ++it) {
                            PcodeOp* op = it->second;
                            if (!op) continue;
                            OpCode code = op->code();
                            if (code != CPUI_CALL && code != CPUI_CALLIND) continue;
                            nCallOps++;
                            uint64_t t = op->getIn(0)->getAddr().getOffset();
                            auto snIt = symbolNames.find(t);
                            if (snIt != symbolNames.end() && importTarget == 0)
                                importTarget = t;
                        }
                        if (nCallOps == 1 && importTarget != 0) {
                            symbolNames[off] = symbolNames[importTarget];
                            isThunk = true;
                        }
                    }
                    if (isThunk) {
                        thunkAddrs.insert(off);
                        rememberOutput(calleeFd);
                        continue;
                    }
                }

                // CRT boundary: decompile CRT functions to discover their
                // non-CRT callees, but don't add CRT to queue or output.
                // The behavioral CRT classification runs in a post-BFS pass.
                bool isCrt = !noCrt && isCrtFunction(calleeFd->getName());
                if (isCrt) {
                    if (std::getenv("ENIGMA_DEBUG"))
                        std::cerr << "    [crt] " << calleeFd->getName() << "\n";
                    // One-level non-CRT callee discovery: immediate user code
                    // called by this CRT function is added to the main queue.
                    for (int4 j = 0; j < calleeFd->numCalls(); ++j) {
                        FuncCallSpecs* fc2 = calleeFd->getCallSpecs(j);
                        const Address& ca2 = fc2->getEntryAddress();
                        if (ca2.isInvalid()) continue;
                        uint64_t off2 = ca2.getOffset();
                        if (visited.count(off2)) continue;
                        visited.insert(off2);
                        Funcdata* fd2 = fc2->getFuncdata();
                        if (!fd2 && off2 >= baseAddr && isExecutableAddress(off2))
                            fd2 = createOrLookup(ca2, fc2->getName(), off2);
                        if (!fd2) continue;
                        if (!isExecutableAddress(off2)) continue;
                        if (fd2->isProcStarted()) {
                            if (!isCrtFunction(fd2->getName()))
                                rememberOutput(fd2);
                            continue;
                        }
                        if (!isCrtFunction(fc2->getName()) && decompileOne(fd2)) {
                            if (std::getenv("ENIGMA_DEBUG"))
                                std::cerr << "    [crt->user] " << fc2->getName() << "\n";
                            bfsMainCandidates.insert(off2);
                            rememberOutput(fd2);
                            userFuncCount++;
                            queue.push_back(fd2);
                            if (maxFuncs > 0 && userFuncCount >= maxFuncs) {
                                queue.clear();
                                break;
                            }
                        }
                    }
                    continue;
                }

                // Normal (non-CRT) function
                rememberOutput(calleeFd);
                userFuncCount++;
                if (maxFuncs > 0 && userFuncCount >= maxFuncs) {
                    if (std::getenv("ENIGMA_DEBUG"))
                        std::cerr << "    [limit] max functions reached\n";
                    queue.clear();
                    break;
                }
                queue.push_back(calleeFd);
            }
        }

        // Behavioral CRT classification replaces the old name-based
        // crtDiscoveryQueue + main renaming. See below for the new
        // post-BFS classification pass.

        if (std::getenv("ENIGMA_DEBUG"))
            std::cerr << "Total functions: " << allFds.size() << "\n";

        // Build complete symbol map from all decompiled functions for resolveFuncRefs
        for (Funcdata* f : allFds) {
            uint64_t off = f->getAddress().getOffset();
            if (off == 0) continue;
            std::string fname = f->getName();
            if (!fname.empty() && symbolNames.find(off) == symbolNames.end()) {
                symbolNames[off] = fname;
            }
        }

        // === RUNTIME ANALYSIS AND ENTRY-POINT RECOVERY FRAMEWORK ===
        // Cross-platform CRT identification based on behavioral signatures.
        // Supports MSVC, UCRT, MinGW, glibc, musl, libstdc++, libc++.
        //
        // Flat registry of known runtime APIs. Each entry maps an API name
        // to a runtime family and an evidence weight.
        struct RuntimeApiEntry { const char* apiName; float weight; const char* runtime; };
        struct Evidence { const char* reason; float weight; };
        static const RuntimeApiEntry runtimeStartupApis[] = {
            {"__getmainargs", 0.40f, "MSVC"},     {"__wgetmainargs", 0.40f, "MSVC"},
            {"_initterm", 0.25f, "MSVC"},          {"_initterm_e", 0.25f, "MSVC"},
            {"__set_app_type", 0.25f, "MSVC"},     {"SetUnhandledExceptionFilter", 0.15f, "MSVC"},
            {"__scrt_initialize_crt", 0.30f,"MSVC"},
            {"__scrt_acquire_startup_lock",0.20f,"MSVC"},
            {"__scrt_release_startup_lock",0.20f,"MSVC"},
            {"_C_specific_handler",0.15f,"MSVC"},  {"_except_handler4_common",0.15f,"MSVC"},
            {"__p___argc",0.10f,"MSVC"},           {"__p___argv",0.10f,"MSVC"},
            {"__p___envp",0.10f,"MSVC"},           {"__initenv",0.10f,"MSVC"},
            {"_cexit",0.15f,"MSVC"},               {"_c_exit",0.15f,"MSVC"},
            {"_crt_atexit",0.15f,"MSVC"},          {"_amsg_exit",0.15f,"MSVC"},
            {"__main",0.35f,"MinGW"},              {"__mingw_app_type",0.25f,"MinGW"},
            {"__mingw_CRTStartup",0.30f,"MinGW"},  {"_fpreset",0.10f,"MinGW"},
            {"__cpu_features_init",0.10f,"MinGW"},
            {"__libc_start_main",0.50f,"glibc"},   {"__libc_start_main",0.50f,"musl"},
            {"__libc_csu_init",0.30f,"glibc"},     {"__libc_csu_fini",0.20f,"glibc"},
            {"__cxa_atexit",0.15f,"glibc"},        {"__cxa_finalize",0.10f,"glibc"},
            {"__init_libc",0.30f,"musl"},          {"__init_tls",0.15f,"musl"},
        };
        static const int runtimeApiCount = sizeof(runtimeStartupApis)/sizeof(runtimeStartupApis[0]);

        // Runtime detection via import/symbol inspection
        auto detectRuntimeEx = [&]() -> const char* {
            for (const auto& pair : symbolNames) {
                const std::string& n = pair.second;
                if (n.find("msvcrt")!=std::string::npos||n.find("ucrtbase")!=std::string::npos) return "MSVC";
                if (n.find("libc.so")!=std::string::npos) {
                    for (const auto& p : symbolNames)
                        if (p.second=="__init_libc") return "musl";
                    return "glibc";
                }
                if (n.find("libmingw")!=std::string::npos) return "MinGW";
            }
            auto eit = symbolNames.find(entryPoint);
            if (eit != symbolNames.end()) {
                if (eit->second.find("mainCRTStartup")==0) return "MSVC";
                if (eit->second=="_start") return "glibc";
            }
            if (isPE) return "MSVC";
            return "glibc";
        };
        const char* detectedRuntime = detectRuntimeEx();
        if (std::getenv("ENIGMA_DEBUG"))
            std::cerr << "[CRT] Runtime detected: " << detectedRuntime << "\n";

        // Build call graph from allFds + entry
        std::unordered_map<uint64_t, std::vector<uint64_t>> callGraph;
        std::unordered_set<uint64_t> allDecompiledAddrs;
        for (Funcdata* fd : allFds) {
            uint64_t off = fd->getAddress().getOffset();
            if (off==0) continue;
            allDecompiledAddrs.insert(off);
            for (int4 i=0;i<fd->numCalls();++i) {
                auto cs=fd->getCallSpecs(i);
                Address ca = cs->getEntryAddress();
                if (!ca.isInvalid() && ca.getSpace() == codeSpace) {
                    uint64_t co = ca.getOffset();
                    if (co!=0) callGraph[off].push_back(co);
                }
            }
        }
        if (entryPoint!=0&&!allDecompiledAddrs.count(entryPoint)) {
            Address eA(codeSpace,(int8)entryPoint);
            Funcdata* eFd=arch->symboltab->getGlobalScope()->queryFunction(eA);
            if (eFd) {
                allDecompiledAddrs.insert(entryPoint);
                for (int4 i=0;i<eFd->numCalls();++i) {
                    auto cs=eFd->getCallSpecs(i);
                    Address ca = cs->getEntryAddress();
                    if (!ca.isInvalid() && ca.getSpace() == codeSpace) {
                        uint64_t co = ca.getOffset();
                        if (co!=0) callGraph[entryPoint].push_back(co);
                    }
                }
            }
        }

        // Evidence-collecting classifier — checks all known runtime APIs
        auto collectEvidence = [&](uint64_t addr) -> std::vector<Evidence> {
            std::vector<Evidence> ev;
            auto ci=callGraph.find(addr);
            if (ci==callGraph.end()) return ev;
            for (uint64_t callee : ci->second) {
                auto si=symbolNames.find(callee);
                if (si==symbolNames.end()) continue;
                for (int ri=0;ri<runtimeApiCount;++ri) {
                    if (si->second==runtimeStartupApis[ri].apiName)
                        ev.push_back({runtimeStartupApis[ri].apiName,runtimeStartupApis[ri].weight});
                }
            }
            return ev;
        };

        struct CrtInfo { float confidence; std::vector<Evidence> evidence; };
        std::unordered_map<uint64_t,CrtInfo> runtimeFunctions;
        std::unordered_set<uint64_t> runtimeSeeds;

        auto addSeed = [&](uint64_t addr, float conf, std::vector<Evidence> ev) {
            if (runtimeSeeds.insert(addr).second) {
                runtimeFunctions[addr]={conf,std::move(ev)};
            }
        };

        for (uint64_t addr : allDecompiledAddrs) {
            auto ev=collectEvidence(addr);
            if (!ev.empty()) {
                float t=0; for (auto& e:ev) t+=e.weight; if (t>1) t=1;
                addSeed(addr,t,ev);
                if (std::getenv("ENIGMA_DEBUG")) {
                    auto si=symbolNames.find(addr);
                    std::cerr<<"[CRT] Seed: 0x"<<std::hex<<addr<<std::dec<<" ("
                             <<(si!=symbolNames.end()?si->second:"?")<<")\n";
                    for (auto& e:ev) std::cerr<<"[CRT]   "<<e.reason<<" +"<<e.weight<<"\n";
                }
                continue;
            }
            if (!noCrt) {
                auto si=symbolNames.find(addr);
                if (si!=symbolNames.end()) {
                    auto& n=si->second;
                    if (isPE&&n[0]=='_') {
                        addSeed(addr,0.50f,{{"name starts with '_'",0.50f}});
                        if (std::getenv("ENIGMA_DEBUG"))
                            std::cerr<<"[CRT] Seed: 0x"<<std::hex<<addr<<std::dec<<" ("<<n
                                     <<")\n[CRT]   name starts with '_' +0.50\n";
                        continue;
                    }
                    for (auto& p : crtPrefixes)
                        if (n.rfind(p,0)==0) {
                            addSeed(addr,0.50f,{{("name matches "+p).c_str(),0.50f}});
                            break;
                        }
                }
            }
        }

        // Propagation: CRT seeds → CRT callees (internal nodes), non-CRT callees → main candidates
        std::unordered_set<uint64_t> classifiedRuntime=runtimeSeeds;
        std::map<uint64_t,float> mainCandidates;
        std::map<uint64_t,std::vector<Evidence>> mainEvidence;
        std::deque<uint64_t> propQ;
        std::unordered_set<uint64_t> propV;
        for (auto s:runtimeSeeds) propQ.push_back(s);

        auto handleMainCandidate = [&](uint64_t callee, uint64_t parent) {
            float conf=0.30f;
            std::vector<Evidence> ev={{"> reachable from runtime boundary",0.30f}};
            auto si=symbolNames.find(callee);
            bool anon=(si==symbolNames.end()||si->second.rfind("sub_0x",0)==0);
            if (anon) { conf+=0.15f; ev.push_back({"> anonymous (likely user code)",0.15f}); }
            auto cc=callGraph.find(callee);
            bool callsRuntime=false;
            if (cc!=callGraph.end())
                for (auto gc:cc->second) if (classifiedRuntime.count(gc)) { callsRuntime=true; break; }
            if (!callsRuntime) { conf+=0.15f; ev.push_back({"> leaf after runtime boundary",0.15f}); }
            if (isPE) {
                auto pc=callGraph.find(parent);
                if (pc!=callGraph.end())
                    for (auto g:pc->second) {
                        auto gi=symbolNames.find(g);
                        if (gi!=symbolNames.end()&&(gi->second=="__getmainargs"||gi->second=="__wgetmainargs"))
                        { conf+=0.10f; ev.push_back({"> parent calls __getmainargs",0.10f}); break; }
                    }
            }
            if (conf>1) conf=1;
            auto ex=mainCandidates.find(callee);
            if (ex==mainCandidates.end()||ex->second<conf) {
                mainCandidates[callee]=conf;
                mainEvidence[callee]=std::move(ev);
            }
            if (std::getenv("ENIGMA_DEBUG"))
                std::cerr<<"[MAIN] Candidate: 0x"<<std::hex<<callee<<std::dec
                         <<"\n[MAIN] Confidence: "<<conf<<"\n";
        };

        while (!propQ.empty()) {
            uint64_t addr=propQ.front(); propQ.pop_front();
            if (!propV.insert(addr).second) continue;
            auto ci=callGraph.find(addr);
            if (ci==callGraph.end()) continue;
            for (uint64_t callee : ci->second) {
                if (callee==0) continue;
                if (propV.count(callee)) continue;
                auto ev=collectEvidence(callee);
                float t=0; for (auto& e:ev) t+=e.weight; if (t>1) t=1;
                if (t>0) {
                    if (classifiedRuntime.insert(callee).second) {
                        runtimeFunctions[callee]={t,std::move(ev)};
                        if (std::getenv("ENIGMA_DEBUG")) {
                            auto si=symbolNames.find(callee);
                            std::cerr<<"[CRT] Boundary: 0x"<<std::hex<<callee<<std::dec<<" ("
                                     <<(si!=symbolNames.end()?si->second:"?")<<")\n";
                            for (auto& e:runtimeFunctions[callee].evidence)
                                std::cerr<<"[CRT]   "<<e.reason<<" +"<<e.weight<<"\n";
                        }
                        propQ.push_back(callee);
                    }
                } else if (classifiedRuntime.count(addr)) {
                    handleMainCandidate(callee,addr);
                }
            }
        }

        // Entry callee chain (when entry itself isn't a runtime function)
        auto eci=callGraph.find(entryPoint);
        if (eci!=callGraph.end()&&!classifiedRuntime.count(entryPoint)) {
            for (uint64_t callee : eci->second) {
                if (callee==0) continue;
                auto ev=collectEvidence(callee);
                float t=0; for (auto& e:ev) t+=e.weight;
                if (t>0&&classifiedRuntime.insert(callee).second) {
                    runtimeFunctions[callee]={t,std::move(ev)};
                    if (std::getenv("ENIGMA_DEBUG")) {
                        auto si=symbolNames.find(callee);
                        std::cerr<<"[CRT] Seed: 0x"<<std::hex<<callee<<std::dec<<" ("
                                 <<(si!=symbolNames.end()?si->second:"?")<<") (entry callee)\n";
                    }
                    propQ.push_back(callee);
                }
            }
            while (!propQ.empty()) {
                uint64_t addr=propQ.front(); propQ.pop_front();
                if (!propV.insert(addr).second) continue;
                auto ci=callGraph.find(addr);
                if (ci==callGraph.end()) continue;
                for (uint64_t callee : ci->second) {
                    if (callee==0) continue;
                    if (propV.count(callee)) continue;
                    auto ev=collectEvidence(callee);
                    float t=0; for (auto& e:ev) t+=e.weight; if (t>1) t=1;
                    if (t>0) {
                        if (classifiedRuntime.insert(callee).second) {
                            runtimeFunctions[callee]={t,std::move(ev)};
                            propQ.push_back(callee);
                        }
                    } else if (classifiedRuntime.count(addr)) {
                        handleMainCandidate(callee,addr);
                    }
                }
            }
        }

        // Select best main candidate
        if (!mainCandidates.empty()) {
            uint64_t bestMainAddr=0;
            float bestConf=0;
            std::vector<Evidence> bestEv;
            for (auto& mc : mainCandidates) {
                auto si=symbolNames.find(mc.first);
                bool anon=(si==symbolNames.end()||si->second.rfind("sub_0x",0)==0);
                float adj=mc.second+(anon?0.08f:0);
                if (adj>bestConf) { bestConf=adj; bestMainAddr=mc.first; auto ei=mainEvidence.find(mc.first); if (ei!=mainEvidence.end()) bestEv=ei->second; }
            }
            if (bestMainAddr!=0) {
                symbolNames[bestMainAddr]="main";
                if (std::getenv("ENIGMA_DEBUG")) {
                    auto si=symbolNames.find(bestMainAddr);
                    std::cerr<<"[MAIN] Selected: 0x"<<std::hex<<bestMainAddr<<std::dec<<" -> main\n[MAIN] Confidence: "<<bestConf<<"\n";
                    for (auto& e:bestEv) std::cerr<<"[MAIN]   "<<e.reason<<" +"<<e.weight<<"\n";
                }
            }

            // Name __main: entry callee that is a main candidate but doesn't call main.
            // In MinGW binaries, __main initializes the C runtime (calls
            // CRT init functions via function pointer table) before main.
            // It's mis-classified as a "main candidate" because it's a
            // non-CRT callee of a CRT function (the entry function).
            // Heuristic: pick the entry callee with lowest main-candidate
            // confidence (least likely to be user code) that doesn't call main.
            if (bestMainAddr != 0) {
                auto entryCgIt = callGraph.find(entryPoint);
                if (entryCgIt != callGraph.end()) {
                    uint64_t mingwMainAddr = 0;
                    for (uint64_t callee : entryCgIt->second) {
                        if (callee == bestMainAddr) continue;
                        // Only consider auto-named functions (sub_0x, func_0x)
                        auto si = symbolNames.find(callee);
                        bool autoNamed = (si == symbolNames.end() ||
                                          si->second.rfind("sub_0x", 0) == 0 ||
                                          si->second.rfind("func_0x", 0) == 0);
                        if (!autoNamed) continue;
                        // Only consider functions that are main candidates
                        auto mcIt = mainCandidates.find(callee);
                        if (mcIt == mainCandidates.end()) continue;
                        // Verify it doesn't call main
                        auto cgIt = callGraph.find(callee);
                        bool callsMain = false;
                        bool callsAtexit = false;
                        if (cgIt != callGraph.end()) {
                            for (uint64_t gc : cgIt->second) {
                                if (gc == bestMainAddr) { callsMain = true; break; }
                                auto gsi = symbolNames.find(gc);
                                if (gsi != symbolNames.end() && gsi->second == "atexit")
                                    callsAtexit = true;
                            }
                        }
                        if (callsMain) continue;
                        // __main calls atexit to register cleanup — this is its signature
                        if (callsAtexit) {
                            mingwMainAddr = callee;
                            break;
                        }
                    }
                    if (mingwMainAddr != 0) {
                        symbolNames[mingwMainAddr] = "__main";
                        if (std::getenv("ENIGMA_DEBUG"))
                            std::cerr << "[MAIN] Named entry callee 0x" << std::hex << mingwMainAddr
                                      << " -> __main" << std::dec << "\n";
                    }
                }
            }
        }

        // Remove thunks from output (they're just extern stubs to imports)
        {
            std::vector<Funcdata*> filtered;
            for (Funcdata* f : allFds) {
                uint64_t off = f->getAddress().getOffset();
                if (thunkAddrs.count(off)) continue;
                filtered.push_back(f);
            }
            allFds.swap(filtered);
        }

    // Generate C output for all functions
    std::ostringstream cStream;
    for (Funcdata* f : allFds) {
        arch->print->setOutputStream(&cStream);
        arch->print->docFunction(f);
        cStream << "\n";
    }

    // Second pass: scan for unresolved sub_0x references and decompile them.
    // This catches callees that the BFS missed due to maxFuncs limit.
    if (maxFuncs > 0) {
        std::string current = cStream.str();
        std::set<uint64_t> unresolvedAddrs;
        const char* subPrefix = "sub_0x";
        for (size_t pos = 0; (pos = current.find(subPrefix, pos)) != std::string::npos; ) {
            pos += 6; // skip "sub_0x"
            size_t end = pos;
            while (end < current.size() && std::isxdigit(static_cast<unsigned char>(current[end])))
                ++end;
            if (end == pos) continue;
            uint64_t addr = std::stoull(current.substr(pos, end - pos), nullptr, 16);
            if (addr != 0 && visited.insert(addr).second)
                unresolvedAddrs.insert(addr);
        }
        if (!unresolvedAddrs.empty() && std::getenv("ENIGMA_DEBUG"))
            std::cerr << "Unresolved refs: " << unresolvedAddrs.size() << "\n";
        for (uint64_t addr : unresolvedAddrs) {
            if (userFuncCount >= maxFuncs) break;
            if (!isExecutableAddress(addr)) continue;
            Address a(codeSpace, static_cast<int8>(addr));
            Funcdata* fd = arch->symboltab->getGlobalScope()->queryFunction(a);
            if (!fd) {
                std::ostringstream oss;
                oss << "sub_0x" << std::hex << addr;
                FunctionSymbol* sym = arch->symboltab->getGlobalScope()->addFunction(a, oss.str());
                if (!sym) continue;
                fd = sym->getFunction();
            }
            if (!fd || fd->isProcStarted()) continue;
            arch->clearAnalysis(fd);
            arch->allacts.getCurrent()->reset(*fd);
            try {
                arch->allacts.getCurrent()->perform(*fd);
                if (typeDB) applyTypeDatabaseToCallSpecs(fd, typeDB.get(), arch->types, arch.get());
            } catch (const LowlevelError&) { continue; }
            if (fd->isProcStarted()) {
                rememberOutput(fd);
                userFuncCount++;
                // Also follow this function's callees
                for (int4 j = 0; j < fd->numCalls(); ++j) {
                    FuncCallSpecs* fc = fd->getCallSpecs(j);
                    const Address& ca = fc->getEntryAddress();
                    if (ca.isInvalid()) continue;
                    uint64_t off2 = ca.getOffset();
                    if (visited.count(off2)) continue;
                    visited.insert(off2);
                    Funcdata* fd2 = fc->getFuncdata();
                    if (fd2 && !isExecutableAddress(fd2->getAddress().getOffset())) continue;
                    if (!fd2 && off2 >= baseAddr && isExecutableAddress(off2))
                        fd2 = createOrLookup(ca, fc->getName(), off2);
                    if (!fd2 || fd2->isProcStarted()) continue;
                    if (!isCrtFunction(fc->getName()) && decompileOne(fd2) && userFuncCount < maxFuncs) {
                        rememberOutput(fd2);
                        userFuncCount++;
                    }
                }
            }
        }
        // Regenerate output with new functions included
        if (!unresolvedAddrs.empty() && allFds.size() > 0) {
            cStream.str("");
            cStream.clear();
            for (Funcdata* f : allFds) {
                arch->print->setOutputStream(&cStream);
                arch->print->docFunction(f);
                cStream << "\n";
            }
        }
    }

    auto tEnd = std::chrono::high_resolution_clock::now();

    if (showTiming) {
        auto entryMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(tEnd - t0).count();
        std::cerr << "Timing:\n"
                  << "  entry decompile: " << entryMs << "ms\n"
                  << "  total: " << totalMs << "ms  (" << allFds.size() << " functions)\n";
    }

    std::string output = cleanOutput(resolveStringRefs(
        resolveFuncRefs(cStream.str(), symbolNames),
        binaryData, baseAddr, detectedBase), rawTypes);
    if (!outputFile.empty()) {
        std::ofstream ofs(outputFile);
        if (!ofs) {
            std::cerr << "Error: Could not open output file: " << outputFile << "\n";
            return 1;
        }
        ofs << output;
    } else {
        std::cout << output;
    }

    return 0;

    } catch (const LowlevelError& le) {
        std::cerr << "LowlevelError: " << le.explain << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception\n";
        return 1;
    }
}
