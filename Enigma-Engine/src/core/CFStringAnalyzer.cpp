#include <ghidra/CFStringAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/MemoryBufferImpl.h>
#include <ghidra/GhidraDataConverter.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/StringDataType.h>
#include <ghidra/Language.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/CommentType.h>
#include <ghidra/AddressSetView.h>

namespace ghidra {

static const std::string CF_STRING_LABEL_PREFIX = "cf_";

CFStringAnalyzer::CFStringAnalyzer()
    : AbstractAnalyzer("CFStrings",
                       "Parses CFString section in MachO files and inserts helpful EOL comment on all xrefs",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool CFStringAnalyzer::canAnalyze(Program* program) const {
    return isMachOAndContainsCFStrings(program);
}

bool CFStringAnalyzer::getDefaultEnablement(Program* program) const {
    return isMachOAndContainsCFStrings(program);
}

bool CFStringAnalyzer::isMachOAndContainsCFStrings(Program* program) const {
    if (!program) return false;
    const std::string& fmt = program->getExecutableFormat();
    if (fmt != "Mac OS X Mach-O") return false;
    return program->getMemory()->getBlock("__cfstring") != nullptr;
}

bool CFStringAnalyzer::added(Program* program, const AddressSetView& set,
                              TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;

    Listing* listing = program->getListing();
    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();

    MemoryBlock* cfstringBlock = memory->getBlock("__cfstring");
    if (!cfstringBlock) return false;

    bool is64Bit = program->getDefaultPointerSize() == 8;

    StructureDataType dataType("cfstringStruct", 0);
    if (is64Bit) {
        dataType.add(&QWordDataType::dataType());
        dataType.add(&QWordDataType::dataType());
        dataType.add(&PointerDataType::dataType(), 8);
        dataType.add(&LongDataType::dataType(), 8);
    } else {
        dataType.add(&DWordDataType::dataType());
        dataType.add(&DWordDataType::dataType());
        dataType.add(&PointerDataType::dataType());
        dataType.add(&IntegerDataType::dataType());
    }
    int recordLen = dataType.getLength();
    int pointerOffset = is64Bit ? 16 : 8;
    int lengthOffset = is64Bit ? 24 : 12;

    MemoryBufferImpl memBuffer(memory, cfstringBlock->getStart());
    const GhidraDataConverter* converter =
        GhidraDataConverter::getConverter(program->getLanguage()->isBigEndian());

    Address currentAddr = cfstringBlock->getStart();
    const Address& endAddr = cfstringBlock->getEnd();

    while (!monitor->isCancelled()) {
        Address structEnd = currentAddr.add(recordLen - 1);
        if (structEnd > endAddr) break;

        Data* data = listing->createData(currentAddr, &dataType);
        if (!data) {
            currentAddr = currentAddr.add(recordLen);
            continue;
        }

        int64_t offset = currentAddr.subtract(cfstringBlock->getStart());
        uint64_t strAddrRaw;
        if (is64Bit) {
            strAddrRaw = static_cast<uint64_t>(converter->getLong(&memBuffer, static_cast<int>(offset + pointerOffset)));
        } else {
            strAddrRaw = static_cast<uint64_t>(converter->getInt(&memBuffer, static_cast<int>(offset + pointerOffset))) & 0xffffffff;
        }

        int64_t length;
        if (is64Bit) {
            length = converter->getLong(&memBuffer, static_cast<int>(offset + lengthOffset));
        } else {
            length = converter->getInt(&memBuffer, static_cast<int>(offset + lengthOffset));
        }

        AddressSpace* defSpace = program->getLanguage()->getDefaultDataSpace();
        if (!defSpace) {
            currentAddr = currentAddr.add(recordLen);
            continue;
        }
        Address strAddr(defSpace, static_cast<int64_t>(strAddrRaw));

        Data* stringData = listing->getDataAt(strAddr);
        if (!stringData) {
            int effectiveLength = (length > 0) ? static_cast<int>(length) : -1;
            listing->createData(strAddr, &StringDataType::dataType(), effectiveLength);
            stringData = listing->getDataAt(strAddr);
        }

        if (stringData) {
            int effectiveLength = (length > 0) ? static_cast<int>(length) : 256;
            std::vector<uint8_t> buf(static_cast<size_t>(effectiveLength) + 1, 0);
            int bytesRead = memory->getBytes(strAddr, buf.data(), effectiveLength);
            if (bytesRead > 0) {
                buf[static_cast<size_t>(bytesRead)] = 0;
                std::string cFString(reinterpret_cast<char*>(buf.data()));
                cFString = cFString.substr(0, cFString.find('\0'));

                CodeUnit* cu = listing->getCodeUnitAt(currentAddr);
                if (cu) {
                    cu->setComment("\"" + cFString + "\",00");
                }

                std::string symbolString = makeLabel(cFString);
                if (!symTable->getGlobalSymbol(symbolString, currentAddr)) {
                    Symbol* sym = symTable->createLabel(currentAddr, symbolString, SourceType::ANALYSIS);
                    if (sym) {
                        sym->setPrimary(true);
                    }
                }
            }
        }

        currentAddr = currentAddr.add(recordLen);
    }

    return true;
}

std::string CFStringAnalyzer::makeComment(const std::string& cFString) const {
    std::string buf;
    for (char c : cFString) {
        switch (c) {
            case '\t': buf += "\\t"; break;
            case '\n': buf += "\\n"; break;
            case '\r': buf += "\\r"; break;
            default:
                if (c >= 0x20 && c < 0x7f) {
                    buf += c;
                } else {
                    buf += '.';
                }
                break;
        }
    }
    return buf;
}

std::string CFStringAnalyzer::makeLabel(const std::string& cFString) const {
    if (cFString.empty()) {
        return CF_STRING_LABEL_PREFIX + "\"\"";
    }

    std::string buf;
    for (char c : cFString) {
        if (c > 0x20 && c < 0x7f) {
            buf += c;
        }
    }

    if (buf.empty()) {
        if (doesStringContainAllSameChars(cFString)) {
            switch (cFString[0]) {
                case '\t': buf = "tab(s)"; break;
                case '\n': buf = "newline(s)"; break;
                case '\r': buf = "creturn(s)"; break;
                case ' ':  buf = "space(s)"; break;
                default:   buf = "."; break;
            }
        } else {
            buf = "format(s)";
        }
    }

    return CF_STRING_LABEL_PREFIX + buf;
}

bool CFStringAnalyzer::doesStringContainAllSameChars(const std::string& str) const {
    if (str.empty()) return true;
    char firstChar = str[0];
    for (size_t i = 1; i < str.size(); i++) {
        if (str[i] != firstChar) return false;
    }
    return true;
}

} // namespace ghidra
