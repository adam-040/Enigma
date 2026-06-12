#include <ghidra/ApplyDataArchiveAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DataTypeArchiveImpl.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/MessageLog.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Options.h>
#include <ghidra/Msg.h>

#include <vector>
#include <string>
#include <cstdint>

namespace ghidra {

static const char* OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
static const char* OPTION_DESCRIPTION_CREATE_BOOKMARKS =
    "If checked, an analysis bookmark will be created at each symbol address "
    "where multiple function definitions were found and not applied.";
static const char* OPTION_NAME_ARCHIVE_CHOOSER = "Archive Chooser";
static const char* OPTION_DESCRIPTION_ARCHIVE_CHOOSER =
    "Specifies the data type archive to apply";

struct TypeDefSpec {
    const char* name;
    const char* category;
    const char* baseType;  // name of an existing built-in type
};

struct StructSpec {
    const char* name;
    const char* category;
};

// --- Windows PE built-in type catalog ---
static const TypeDefSpec WINDOWS_TYPEDEFS[] = {
    {"DWORD",      "/Windows", "uint"},
    {"DWORD32",    "/Windows", "uint32"},
    {"DWORD64",    "/Windows", "uint64"},
    {"INT",        "/Windows", "int32"},
    {"INT32",      "/Windows", "int32"},
    {"INT64",      "/Windows", "int64"},
    {"UINT",       "/Windows", "uint32"},
    {"UINT32",     "/Windows", "uint32"},
    {"UINT64",     "/Windows", "uint64"},
    {"LONG",       "/Windows", "int32"},
    {"ULONG",      "/Windows", "uint32"},
    {"LONG64",     "/Windows", "int64"},
    {"ULONG64",    "/Windows", "uint64"},
    {"BOOL",       "/Windows", "int32"},
    {"BOOLEAN",    "/Windows", "byte"},
    {"BYTE",       "/Windows", "byte"},
    {"WORD",       "/Windows", "ushort"},
    {"CHAR",       "/Windows", "char"},
    {"UCHAR",      "/Windows", "byte"},
    {"SHORT",      "/Windows", "short"},
    {"USHORT",     "/Windows", "ushort"},
    {"WCHAR",      "/Windows", "wchar16"},
    {"HRESULT",    "/Windows", "int32"},
    {"NTSTATUS",   "/Windows", "int32"},
    {"SIZE_T",     "/Windows", "uint"},
    {"DWORD_PTR",  "/Windows", "uint"},
    {"INT_PTR",    "/Windows", "int"},
    {"UINT_PTR",   "/Windows", "uint"},
    {"LONG_PTR",   "/Windows", "int"},
    {"ULONG_PTR",  "/Windows", "uint"},
    {"LPARAM",     "/Windows", "long"},
    {"WPARAM",     "/Windows", "uint"},
    {"LRESULT",    "/Windows", "long"},
    {"ATOM",       "/Windows", "ushort"},
    {"HANDLE",     "/Windows", "void*"},
    {"HMODULE",    "/Windows", "void*"},
    {"HINSTANCE",  "/Windows", "void*"},
    {"HWND",       "/Windows", "void*"},
    {"HDC",        "/Windows", "void*"},
    {"HGDIOBJ",    "/Windows", "void*"},
    {"HFONT",      "/Windows", "void*"},
    {"HPEN",       "/Windows", "void*"},
    {"HBRUSH",     "/Windows", "void*"},
    {"HBITMAP",    "/Windows", "void*"},
    {"HMENU",      "/Windows", "void*"},
    {"HICON",      "/Windows", "void*"},
    {"HCURSOR",    "/Windows", "void*"},
    {"HKEY",       "/Windows", "void*"},
    {"SC_HANDLE",  "/Windows", "void*"},
    {"LPVOID",     "/Windows", "void*"},
    {"LPCVOID",    "/Windows", "void*"},
    {"LPSTR",      "/Windows", "char*"},
    {"LPCSTR",     "/Windows", "char*"},
    {"LPWSTR",     "/Windows", "wchar16*"},
    {"LPCWSTR",    "/Windows", "wchar16*"},
    {"LPTSTR",     "/Windows", "char*"},
    {"LPTCH",      "/Windows", "char*"},
    {"COLORREF",   "/Windows", "uint32"},
};

// --- GCC/ELF built-in type catalog ---
static const TypeDefSpec GCC_TYPEDEFS[] = {
    {"size_t",       "/gcc", "uint"},
    {"ssize_t",      "/gcc", "int"},
    {"ptrdiff_t",    "/gcc", "int"},
    {"int8_t",       "/gcc", "int8"},
    {"int16_t",      "/gcc", "short"},
    {"int32_t",      "/gcc", "int"},
    {"int64_t",      "/gcc", "longlong"},
    {"uint8_t",      "/gcc", "byte"},
    {"uint16_t",     "/gcc", "ushort"},
    {"uint32_t",     "/gcc", "uint"},
    {"uint64_t",     "/gcc", "ulonglong"},
    {"intptr_t",     "/gcc", "int"},
    {"uintptr_t",    "/gcc", "uint"},
    {"wchar_t",      "/gcc", "wchar16"},
    {"va_list",      "/gcc", "char*"},
    {"FILE",         "/gcc", "void*"},
    {"off_t",        "/gcc", "long"},
    {"mode_t",       "/gcc", "uint"},
    {"pid_t",        "/gcc", "int"},
    {"uid_t",        "/gcc", "uint"},
    {"gid_t",        "/gcc", "uint"},
};

ApplyDataArchiveAnalyzer::ApplyDataArchiveAnalyzer()
    : AbstractAnalyzer("Apply Data Archives",
                       "Applies known data type archives to the program.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.before());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

void ApplyDataArchiveAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled_,
                         OPTION_DESCRIPTION_CREATE_BOOKMARKS);
    options.registerString(OPTION_NAME_ARCHIVE_CHOOSER, archiveChooser_,
                           OPTION_DESCRIPTION_ARCHIVE_CHOOSER);
}

void ApplyDataArchiveAnalyzer::optionsChanged(Options& options, Program* program) {
    createBookmarksEnabled_ = options.getBool(OPTION_NAME_CREATE_BOOKMARKS);
    archiveChooser_ = options.getString(OPTION_NAME_ARCHIVE_CHOOSER);
}

static DataType* resolveBaseType(DataTypeManager* dtm, const std::string& baseName, int ptrSize) {
    // Map shorthand names to actual types
    if (baseName == "void*") {
        PointerDataType* ptr = new PointerDataType(dtm);
        dtm->addDataType(ptr, nullptr);
        return ptr;
    }
    if (baseName == "char*") {
        DataType* charType = dtm->getDataType(CategoryPath::ROOT(), "char");
        if (!charType) charType = dtm->getDataType(CategoryPath::ROOT(), "byte");
        PointerDataType* ptr = new PointerDataType(dtm);
        dtm->addDataType(ptr, nullptr);
        return ptr;
    }
    if (baseName == "wchar16*") {
        PointerDataType* ptr = new PointerDataType(dtm);
        dtm->addDataType(ptr, nullptr);
        return ptr;
    }

    // Standard base types
    static const struct {
        const char* name;
        const char* builtinPath;
    } baseMap[] = {
        {"void",       "void"},
        {"byte",       "byte"},
        {"char",       "char"},
        {"short",      "short"},
        {"ushort",     "ushort"},
        {"int",        "int"},
        {"uint",       "uint"},
        {"int8",       "byte"},
        {"int16",      "short"},
        {"int32",      "int"},
        {"int64",      "longlong"},
        {"uint8",      "byte"},
        {"uint16",     "ushort"},
        {"uint32",     "uint"},
        {"uint64",     "ulonglong"},
        {"long",       "long"},
        {"ulong",      "ulong"},
        {"longlong",   "longlong"},
        {"ulonglong",  "ulonglong"},
        {"float",      "float"},
        {"double",     "double"},
        {"wchar16",    "ushort"},
        {"bool",       "bool"},
        {nullptr, nullptr}
    };

    for (int i = 0; baseMap[i].name; ++i) {
        if (baseName == baseMap[i].name) {
            return dtm->getDataType(CategoryPath::ROOT(), baseMap[i].builtinPath);
        }
    }
    return nullptr;
}

static void populateArchive(DataTypeArchiveImpl* archive, const TypeDefSpec* specs, int count) {
    DataTypeManagerImpl* dtm = archive->getDataTypeManagerImpl();
    int ptrSize = archive->getDefaultPointerSize();

    for (int i = 0; i < count; ++i) {
        const TypeDefSpec& spec = specs[i];
        DataType* baseType = resolveBaseType(dtm, spec.baseType, ptrSize);
        if (!baseType) continue;

        CategoryPath catPath(spec.category);
        TypedefDataType* td = new TypedefDataType(catPath, spec.name, baseType, dtm);
        dtm->addDataType(td);
    }
}

bool ApplyDataArchiveAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    DataTypeManager* progDTM = program->getDataTypeManager();
    if (!progDTM) return true;

    if (monitor) monitor->setMessage("Applying standard data type archives...");

    const std::string& format = program->getExecutableFormat();
    Language* lang = program->getLanguage();
    int ptrSize = lang ? (lang->getDefaultSpace()->getSize() / 8) : 4;

    bool isPE = (format.find("PE") != std::string::npos ||
                 format.find("Portable Executable") != std::string::npos);
    bool isELF = (format.find("ELF") != std::string::npos);
    bool isMacho = (format.find("Mach-O") != std::string::npos ||
                    format.find("macho") != std::string::npos ||
                    format.find("MACHO") != std::string::npos);

    if (monitor) {
        monitor->setMessage(getName() + ": Detected format: " + format);
    }
    Msg::info(getName(), "Detected format: " + format + ", pointer size=" + std::to_string(ptrSize));

    int totalTypesAdded = 0;

    if (isPE) {
        if (monitor) monitor->setMessage(getName() + ": Applying Windows type archive...");
        DataTypeArchiveImpl winArchive("Windows Archive", ptrSize);
        populateArchive(&winArchive, WINDOWS_TYPEDEFS,
                        sizeof(WINDOWS_TYPEDEFS) / sizeof(WINDOWS_TYPEDEFS[0]));

        DataTypeManager* winDTM = winArchive.getDataTypeManager();
        std::vector<DataType*> types = winDTM->getDataTypes();
        for (auto* dt : types) {
            if (monitor && monitor->isCancelled()) break;
            if (!dt) continue;

            // Skip built-in primitives (they already exist in the program)
            std::string name = dt->getName();
            if (name == "void" || name == "bool" || name == "byte" || name == "char" ||
                name == "short" || name == "ushort" || name == "int" || name == "uint" ||
                name == "long" || name == "ulong" || name == "longlong" || name == "ulonglong" ||
                name == "float" || name == "double" || name == "string") continue;

            // Check if type already exists in program
            CategoryPath catPath = dt->getCategoryPath();
            if (progDTM->getDataType(catPath, name)) continue;

            DataType* clone = dt->clone(progDTM);
            if (clone) {
                DataType* resolved = progDTM->resolve(clone, nullptr);
                if (resolved) ++totalTypesAdded;
            }
        }
        Msg::info(getName(), "Applied " + std::to_string(totalTypesAdded) +
                  " Windows data types to program");
    }

    if (isELF) {
        if (monitor) monitor->setMessage(getName() + ": Applying GCC type archive...");
        DataTypeArchiveImpl gccArchive("GCC Archive", ptrSize);
        populateArchive(&gccArchive, GCC_TYPEDEFS,
                        sizeof(GCC_TYPEDEFS) / sizeof(GCC_TYPEDEFS[0]));

        DataTypeManager* gccDTM = gccArchive.getDataTypeManager();
        std::vector<DataType*> types = gccDTM->getDataTypes();
        for (auto* dt : types) {
            if (monitor && monitor->isCancelled()) break;
            if (!dt) continue;

            std::string name = dt->getName();
            if (name == "void" || name == "bool" || name == "byte" || name == "char" ||
                name == "short" || name == "ushort" || name == "int" || name == "uint" ||
                name == "long" || name == "ulong" || name == "longlong" || name == "ulonglong" ||
                name == "float" || name == "double" || name == "string") continue;

            CategoryPath catPath = dt->getCategoryPath();
            if (progDTM->getDataType(catPath, name)) continue;

            DataType* clone = dt->clone(progDTM);
            if (clone) {
                DataType* resolved = progDTM->resolve(clone, nullptr);
                if (resolved) ++totalTypesAdded;
            }
        }
        Msg::info(getName(), "Applied " + std::to_string(totalTypesAdded) +
                  " GCC data types to program");
    }

    if (isMacho) {
        // macOS uses similar types to GCC/BSD
        if (monitor) monitor->setMessage(getName() + ": Applying Mach-O type archive...");
        DataTypeArchiveImpl machArchive("Mach-O Archive", ptrSize);
        populateArchive(&machArchive, GCC_TYPEDEFS,
                        sizeof(GCC_TYPEDEFS) / sizeof(GCC_TYPEDEFS[0]));

        DataTypeManager* mDTM = machArchive.getDataTypeManager();
        std::vector<DataType*> types = mDTM->getDataTypes();
        for (auto* dt : types) {
            if (monitor && monitor->isCancelled()) break;
            if (!dt) continue;

            std::string name = dt->getName();
            if (name == "void" || name == "bool" || name == "byte" || name == "char" ||
                name == "short" || name == "ushort" || name == "int" || name == "uint" ||
                name == "long" || name == "ulong" || name == "longlong" || name == "ulonglong" ||
                name == "float" || name == "double" || name == "string") continue;

            CategoryPath catPath = dt->getCategoryPath();
            if (progDTM->getDataType(catPath, name)) continue;

            DataType* clone = dt->clone(progDTM);
            if (clone) {
                DataType* resolved = progDTM->resolve(clone, nullptr);
                if (resolved) ++totalTypesAdded;
            }
        }
        Msg::info(getName(), "Applied " + std::to_string(totalTypesAdded) +
                  " Mach-O data types to program");
    }

    if (!isPE && !isELF && !isMacho) {
        Msg::info(getName(), "Unknown executable format '" + format +
                  "'. No standard data types applied.");
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Applied " + std::to_string(totalTypesAdded) +
                            " standard data types");
    }

    return true;
}

} // namespace ghidra
