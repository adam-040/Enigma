#include <ghidra/JavaAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/LanguageID.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Namespace.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/StringDataType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>

#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <cstring>
#include <algorithm>

namespace ghidra {

// Constant pool tag constants
static const uint8_t CONSTANT_Utf8 = 1;
static const uint8_t CONSTANT_Integer = 3;
static const uint8_t CONSTANT_Float = 4;
static const uint8_t CONSTANT_Long = 5;
static const uint8_t CONSTANT_Double = 6;
static const uint8_t CONSTANT_Class = 7;
static const uint8_t CONSTANT_String = 8;
static const uint8_t CONSTANT_Fieldref = 9;
static const uint8_t CONSTANT_Methodref = 10;
static const uint8_t CONSTANT_InterfaceMethodref = 11;
static const uint8_t CONSTANT_NameAndType = 12;
static const uint8_t CONSTANT_MethodHandle = 15;
static const uint8_t CONSTANT_MethodType = 16;
static const uint8_t CONSTANT_InvokeDynamic = 18;
static const uint8_t CONSTANT_Module = 19;
static const uint8_t CONSTANT_Package = 20;

// Access flags
static const uint16_t ACC_PUBLIC = 0x0001;
static const uint16_t ACC_PRIVATE = 0x0002;
static const uint16_t ACC_PROTECTED = 0x0004;
static const uint16_t ACC_STATIC = 0x0008;
static const uint16_t ACC_FINAL = 0x0010;
static const uint16_t ACC_SUPER = 0x0020;
static const uint16_t ACC_NATIVE = 0x0100;
static const uint16_t ACC_ABSTRACT = 0x0400;
static const uint16_t ACC_STRICT = 0x0800;

static uint16_t r16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
}

static uint32_t r32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           (static_cast<uint32_t>(p[3]));
}

struct ConstantPoolEntry {
    uint8_t tag;
    std::vector<uint8_t> raw;
    union {
        struct { uint16_t nameIndex; uint16_t descriptorIndex; } nameAndType;
        struct { uint16_t classIndex; uint16_t nameAndTypeIndex; } ref;
        struct { uint16_t stringIndex; } string;
        struct { uint16_t classIndex; } cls;
        struct { uint16_t nameIndex; } utfs;
        struct { uint16_t methodTypeIndex; } methodType;
        struct { uint16_t bootstrapMethodAttrIndex; uint16_t nameAndTypeIndex; } invokeDynamic;
        uint32_t bytes;
        uint64_t bytes64;
    };
    std::string utf8String;
};

static std::string descriptorToReadable(const std::string& desc) {
    if (desc.empty()) return "void";
    if (desc[0] == 'B') return "byte";
    if (desc[0] == 'C') return "char";
    if (desc[0] == 'D') return "double";
    if (desc[0] == 'F') return "float";
    if (desc[0] == 'I') return "int";
    if (desc[0] == 'J') return "long";
    if (desc[0] == 'S') return "short";
    if (desc[0] == 'Z') return "boolean";
    if (desc[0] == 'V') return "void";
    if (desc[0] == '[') {
        int dims = 0;
        while (dims < static_cast<int>(desc.size()) && desc[static_cast<size_t>(dims)] == '[') ++dims;
        std::string elem = descriptorToReadable(desc.substr(static_cast<size_t>(dims)));
        return elem + std::string(static_cast<size_t>(dims), ']');
    }
    if (desc[0] == 'L') {
        auto semi = desc.find(';');
        if (semi != std::string::npos) {
            std::string cls = desc.substr(1, semi - 1);
            std::replace(cls.begin(), cls.end(), '/', '.');
            return cls;
        }
        return desc;
    }
    if (desc[0] == '(') {
        auto close = desc.find(')');
        if (close == std::string::npos) return desc;
        std::string params = desc.substr(1, close - 1);
        std::string ret = descriptorToReadable(desc.substr(close + 1));
        std::string result = "(";
        size_t pos = 0;
        int paramIdx = 0;
        while (pos < params.size()) {
            if (params[pos] == '[') {
                int dims = 0;
                while (pos < params.size() && params[pos] == '[') { ++pos; ++dims; }
                std::string base = descriptorToReadable(params.substr(pos, 1));
                result += base + std::string(static_cast<size_t>(dims), ']');
                ++pos;
            } else if (params[pos] == 'L') {
                auto semi = params.find(';', pos);
                if (semi == std::string::npos) break;
                std::string cls = params.substr(pos + 1, semi - pos - 1);
                std::replace(cls.begin(), cls.end(), '/', '.');
                result += cls;
                pos = semi + 1;
            } else {
                result += descriptorToReadable(params.substr(pos, 1));
                ++pos;
            }
            if (pos < params.size()) result += ",";
            ++paramIdx;
        }
        result += ")";
        result += ret;
        return result;
    }
    return desc;
}

JavaAnalyzer::JavaAnalyzer()
    : AbstractJavaAnalyzer("Java Class Analyzer",
                           "Analyzes Java .class files.",
                           AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool JavaAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    std::string langId = program->getLanguageID().getIdAsString();
    if (langId.find("JVM") != std::string::npos || langId.find("jvm") != std::string::npos) return true;
    if (!program->getMemory()) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = program->getMemory()->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[4] = {0};
    if (program->getMemory()->getBytes(minAddr, buf, 4) != 4) return false;
    return buf[0] == 0xCA && buf[1] == 0xFE && buf[2] == 0xBA && buf[3] == 0xBE;
}

bool JavaAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool JavaAnalyzer::analyze(Program* program, const AddressSetView& set,
                            TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    FunctionManager* funcMgr = program->getFunctionManager();
    DataTypeManager* dtm = program->getDataTypeManager();
    if (!memory || !listing || !symTable || !funcMgr || !dtm) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address baseAddr(space, 0);

    if (monitor) monitor->setMessage("Parsing Java class file...");

    // Read the entire class file
    MemoryBlock* block = memory->getBlock(baseAddr);
    if (!block) return true;

    int64_t fileSize = block->getEnd().getOffset() - block->getStart().getOffset() + 1;
    if (fileSize < 8) return true;

    std::vector<uint8_t> raw(static_cast<size_t>(fileSize));
    if (memory->getBytes(baseAddr, raw.data(), static_cast<int>(fileSize)) != static_cast<int>(fileSize)) return true;

    int pos = 0;

    // Parse header
    uint32_t magic = r32(&raw[static_cast<size_t>(pos)]); pos += 4;
    if (magic != 0xCAFEBABE) return true;

    uint16_t minorVersion = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
    uint16_t majorVersion = r16(&raw[static_cast<size_t>(pos)]); pos += 2;

    if (monitor) {
        monitor->setMessage(getName() + ": Java class v" + std::to_string(majorVersion) +
                            "." + std::to_string(minorVersion));
    }

    // Parse constant pool
    uint16_t cpCount = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
    std::vector<ConstantPoolEntry> cp(static_cast<size_t>(cpCount));
    std::vector<int> cpOffset(static_cast<size_t>(cpCount), 0); // offset of CP entry in file

    for (int cpi = 1; cpi < static_cast<int>(cpCount); ++cpi) {
        if (pos >= static_cast<int>(fileSize)) break;
        cpOffset[static_cast<size_t>(cpi)] = pos;

        cp[static_cast<size_t>(cpi)].tag = raw[static_cast<size_t>(pos++)];

        size_t ci = static_cast<size_t>(cpi);
        switch (cp[ci].tag) {
        case CONSTANT_Utf8: {
            uint16_t len = r16(&raw[static_cast<size_t>(pos)]);
            cpOffset[ci] = pos;
            pos += 2;
            if (pos + len > static_cast<int>(fileSize)) break;
            cp[ci].utf8String.assign(reinterpret_cast<char*>(&raw[static_cast<size_t>(pos)]), len);
            pos += len;
            break;
        }
        case CONSTANT_Integer:
        case CONSTANT_Float: {
            cp[ci].bytes = r32(&raw[static_cast<size_t>(pos)]);
            pos += 4;
            break;
        }
        case CONSTANT_Long:
        case CONSTANT_Double: {
            cp[ci].bytes64 = (static_cast<uint64_t>(r32(&raw[static_cast<size_t>(pos)])) << 32) |
                              r32(&raw[static_cast<size_t>(pos + 4)]);
            pos += 8;
            ++cpi; // Long/Double take two constant pool entries
            break;
        }
        case CONSTANT_Class:
        case CONSTANT_Module:
        case CONSTANT_Package: {
            cp[ci].cls.classIndex = r16(&raw[static_cast<size_t>(pos)]);
            pos += 2;
            break;
        }
        case CONSTANT_String: {
            cp[ci].string.stringIndex = r16(&raw[static_cast<size_t>(pos)]);
            pos += 2;
            break;
        }
        case CONSTANT_Fieldref:
        case CONSTANT_Methodref:
        case CONSTANT_InterfaceMethodref: {
            cp[ci].ref.classIndex = r16(&raw[static_cast<size_t>(pos)]);
            cp[ci].ref.nameAndTypeIndex = r16(&raw[static_cast<size_t>(pos + 2)]);
            pos += 4;
            break;
        }
        case CONSTANT_NameAndType: {
            cp[ci].nameAndType.nameIndex = r16(&raw[static_cast<size_t>(pos)]);
            cp[ci].nameAndType.descriptorIndex = r16(&raw[static_cast<size_t>(pos + 2)]);
            pos += 4;
            break;
        }
        case CONSTANT_MethodHandle: {
            pos += 1; // reference_kind
            cp[ci].ref.classIndex = r16(&raw[static_cast<size_t>(pos)]);
            pos += 2;
            break;
        }
        case CONSTANT_MethodType: {
            cp[ci].methodType.methodTypeIndex = r16(&raw[static_cast<size_t>(pos)]);
            pos += 2;
            break;
        }
        case CONSTANT_InvokeDynamic: {
            cp[ci].invokeDynamic.bootstrapMethodAttrIndex = r16(&raw[static_cast<size_t>(pos)]);
            cp[ci].invokeDynamic.nameAndTypeIndex = r16(&raw[static_cast<size_t>(pos + 2)]);
            pos += 4;
            break;
        }
        default:
            break;
        }
    }

    // Get class name from this_class
    uint16_t accessFlags = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
    uint16_t thisClass = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
    uint16_t superClass = r16(&raw[static_cast<size_t>(pos)]); pos += 2;

    std::string className;
    if (thisClass > 0 && thisClass < cpCount) {
        uint16_t nameIdx = cp[static_cast<size_t>(thisClass)].cls.classIndex;
        if (nameIdx > 0 && nameIdx < cpCount) {
            className = cp[static_cast<size_t>(nameIdx)].utf8String;
            std::replace(className.begin(), className.end(), '/', '.');
        }
    }

    if (className.empty()) className = "UnknownClass";

    if (monitor) {
        monitor->setMessage(getName() + ": Parsing class " + className);
    }

    // Create class namespace
    std::string nsName = className;
    auto dotPos = nsName.rfind('.');
    std::string simpleName = (dotPos != std::string::npos) ? nsName.substr(dotPos + 1) : nsName;
    std::string pkgName = (dotPos != std::string::npos) ? nsName.substr(0, dotPos) : "";

    Namespace* classNs = nullptr;
    if (pkgName.empty()) {
        classNs = symTable->createNameSpace(symTable->getGlobalNamespace(), simpleName, SourceType::ANALYSIS);
    } else {
        Namespace* pkgNs = symTable->createNameSpace(symTable->getGlobalNamespace(), pkgName, SourceType::ANALYSIS);
        classNs = symTable->createNameSpace(pkgNs, simpleName, SourceType::ANALYSIS);
    }

    // Create label for the class at the beginning
    symTable->createLabel(baseAddr, simpleName, classNs, SourceType::ANALYSIS);

    // Skip interfaces
    uint16_t ifCount = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
    pos += ifCount * 2;

    if (monitor) monitor->setMessage(getName() + ": Parsing fields...");

    // Parse fields
    uint16_t fieldCount = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
    for (int fi = 0; fi < fieldCount; ++fi) {
        if (pos + 6 > static_cast<int>(fileSize)) break;
        uint16_t fAccess = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
        uint16_t fNameIdx = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
        uint16_t fDescIdx = r16(&raw[static_cast<size_t>(pos)]); pos += 2;

        std::string fieldName = (fNameIdx > 0 && fNameIdx < cpCount) ? cp[static_cast<size_t>(fNameIdx)].utf8String : "unknown";
        std::string fieldDesc = (fDescIdx > 0 && fDescIdx < cpCount) ? cp[static_cast<size_t>(fDescIdx)].utf8String : "";

        (void)fAccess;

        // Skip field attributes
        uint16_t fAttrCount = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
        for (int fai = 0; fai < fAttrCount; ++fai) {
            if (pos + 6 > static_cast<int>(fileSize)) break;
            pos += 2; // attribute_name_index
            uint32_t fAttrLen = r32(&raw[static_cast<size_t>(pos)]); pos += 4;
            pos += static_cast<int>(fAttrLen);
        }

        // Create field label at its offset position
        if (!fieldName.empty() && fieldName[0] != '\0' && pos >= 0 && pos < static_cast<int>(fileSize)) {
            // Field data starts at its current position in the file
            // For static final fields with ConstantValue, we could label the value location
            // For now, just note the field was found
        }
    }

    if (monitor) monitor->setMessage(getName() + ": Parsing methods...");

    // Parse methods
    uint16_t methodCount = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
    int totalMethods = 0;

    for (int mi = 0; mi < methodCount; ++mi) {
        if (monitor && monitor->isCancelled()) break;
        if (pos + 6 > static_cast<int>(fileSize)) break;

        int methodStartPos = pos;
        uint16_t mAccess = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
        uint16_t mNameIdx = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
        uint16_t mDescIdx = r16(&raw[static_cast<size_t>(pos)]); pos += 2;

        std::string methodName = (mNameIdx > 0 && mNameIdx < cpCount) ? cp[static_cast<size_t>(mNameIdx)].utf8String : "unknown";
        std::string methodDesc = (mDescIdx > 0 && mDescIdx < cpCount) ? cp[static_cast<size_t>(mDescIdx)].utf8String : "";

        bool isNative = (mAccess & ACC_NATIVE) != 0;
        bool isAbstract = (mAccess & ACC_ABSTRACT) != 0;
        bool isStatic = (mAccess & ACC_STATIC) != 0;
        (void)isAbstract;
        (void)isStatic;

        // Parse method attributes
        uint16_t mAttrCount = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
        bool hasCode = false;
        int codeOffset = 0;
        uint32_t codeLength = 0;

        for (int mai = 0; mai < mAttrCount; ++mai) {
            if (pos + 6 > static_cast<int>(fileSize)) break;
            uint16_t attrNameIdx = r16(&raw[static_cast<size_t>(pos)]); pos += 2;
            uint32_t attrLen = r32(&raw[static_cast<size_t>(pos)]); pos += 4;

            std::string attrName = (attrNameIdx > 0 && attrNameIdx < cpCount) ? cp[static_cast<size_t>(attrNameIdx)].utf8String : "";
            int attrDataStart = pos;

            if (attrName == "Code") {
                hasCode = true;
                // Code attribute:
                // max_stack(2), max_locals(2), code_length(4), code[code_length],
                // exception_table_length(2), exception_table[], attributes_count(2), attributes[]
                if (attrDataStart + 8 > static_cast<int>(fileSize)) break;

                uint32_t codeLen = r32(&raw[static_cast<size_t>(attrDataStart + 4)]);
                codeOffset = attrDataStart + 8;
                codeLength = codeLen;

                if (isNative) hasCode = false;
            }

            pos += static_cast<int>(attrLen);
            if (pos > static_cast<int>(fileSize)) pos = static_cast<int>(fileSize);
        }

        if (hasCode && codeLength > 0 && codeOffset > 0) {
            Address codeAddr(space, codeOffset);

            // Create the function
            std::string funcName = methodName;
            std::string fullFuncName = methodName;

            // Create a label and function at the code offset
            if (!listing->isUndefined(codeAddr) && listing->getInstructionAt(codeAddr)) {
                // Already has code at this address - still create function
            }

            // Set up the function body (code block)
            AddressSet funcBody;
            Address codeEnd = Address(space, codeOffset + static_cast<int>(codeLength) - 1);
            funcBody.addRange(codeAddr, codeEnd);

            // Create the function
            Function* func = funcMgr->createFunction(fullFuncName, classNs, codeAddr, funcBody, SourceType::ANALYSIS);
            if (func) {
                ++totalMethods;
            }

            // Also create a label at the method offset (pointing to the method_info)
            Address methodAddr(space, methodStartPos);
            symTable->createLabel(methodAddr, methodName + "_info", classNs, SourceType::ANALYSIS);
        }

        if (monitor) {
            monitor->setProgress(mi * 100 / std::max(methodCount, (uint16_t)1));
        }
    }

    // Create structure types for constant pool entries
    if (monitor) monitor->setMessage(getName() + ": Labeling constant pool...");
    int totalCpLabels = 0;

    for (int cpi = 1; cpi < static_cast<int>(cpCount); ++cpi) {
        if (monitor && monitor->isCancelled()) break;

        size_t ci = static_cast<size_t>(cpi);
        int off = cpOffset[ci];
        if (off <= 0 || off >= static_cast<int>(fileSize)) continue;

        Address cpAddr(space, off);
        if (!listing->isUndefined(cpAddr)) continue;

        // Create labels for interesting CP entries
        switch (cp[ci].tag) {
        case CONSTANT_Utf8:
            if (!cp[ci].utf8String.empty()) {
                symTable->createLabel(cpAddr, "utf8_" + cp[ci].utf8String, SourceType::ANALYSIS);
                ++totalCpLabels;
            }
            break;
        case CONSTANT_Class:
            if (cp[ci].cls.classIndex > 0 && cp[ci].cls.classIndex < cpCount) {
                std::string clsName = cp[static_cast<size_t>(cp[ci].cls.classIndex)].utf8String;
                std::replace(clsName.begin(), clsName.end(), '/', '.');
                symTable->createLabel(cpAddr, "class_" + clsName, SourceType::ANALYSIS);
                ++totalCpLabels;
            }
            break;
        case CONSTANT_String:
            if (cp[ci].string.stringIndex > 0 && cp[ci].string.stringIndex < cpCount) {
                std::string strVal = cp[static_cast<size_t>(cp[ci].string.stringIndex)].utf8String;
                symTable->createLabel(cpAddr, "str_" + strVal, SourceType::ANALYSIS);
                ++totalCpLabels;
            }
            break;
        case CONSTANT_Methodref:
        case CONSTANT_InterfaceMethodref: {
            if (cp[ci].ref.nameAndTypeIndex > 0 && cp[ci].ref.nameAndTypeIndex < cpCount) {
                uint16_t ntNameIdx = cp[static_cast<size_t>(cp[ci].ref.nameAndTypeIndex)].nameAndType.nameIndex;
                if (ntNameIdx > 0 && ntNameIdx < cpCount) {
                    std::string refName = cp[static_cast<size_t>(ntNameIdx)].utf8String;
                    symTable->createLabel(cpAddr, "method_" + refName, SourceType::ANALYSIS);
                    ++totalCpLabels;
                }
            }
            break;
        }
        case CONSTANT_Fieldref: {
            if (cp[ci].ref.nameAndTypeIndex > 0 && cp[ci].ref.nameAndTypeIndex < cpCount) {
                uint16_t ntNameIdx = cp[static_cast<size_t>(cp[ci].ref.nameAndTypeIndex)].nameAndType.nameIndex;
                if (ntNameIdx > 0 && ntNameIdx < cpCount) {
                    std::string refName = cp[static_cast<size_t>(ntNameIdx)].utf8String;
                    symTable->createLabel(cpAddr, "field_" + refName, SourceType::ANALYSIS);
                    ++totalCpLabels;
                }
            }
            break;
        }
        default:
            break;
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(totalMethods) +
                            " methods, " + std::to_string(totalCpLabels) + " CP labels for " + className);
    }

    Msg::info(getName(), "Analyzed Java class '" + className + "' v" +
              std::to_string(majorVersion) + "." + std::to_string(minorVersion) + ": " +
              std::to_string(totalMethods) + " methods, " +
              std::to_string(totalCpLabels) + " constant pool labels");

    return true;
}

} // namespace ghidra
