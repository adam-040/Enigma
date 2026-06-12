#include <ghidra/DWARFAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Listing.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/UnsignedIntegerDataType.h>
#include <ghidra/UnsignedLongDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/DoubleDataType.h>
#include <ghidra/CharDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/Undefined4DataType.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Language.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/MessageLog.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Options.h>
#include <ghidra/Msg.h>
#include <ghidra/ULEB128.h>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cctype>
#include <fstream>
#include <algorithm>
#include <map>

namespace ghidra {

namespace {

enum : uint32_t {
    DW_TAG_compile_unit      = 0x11,
    DW_TAG_subprogram        = 0x2e,
    DW_TAG_variable          = 0x34,
    DW_TAG_namespace         = 0x39,
    DW_TAG_lexical_block     = 0x0b,
    DW_TAG_base_type         = 0x24,
    DW_TAG_pointer_type      = 0x0f,
    DW_TAG_structure_type    = 0x13,
    DW_TAG_class_type        = 0x02,
    DW_TAG_union_type        = 0x17,
    DW_TAG_enumeration_type  = 0x04,
    DW_TAG_typedef           = 0x16,
    DW_TAG_array_type        = 0x01,
    DW_TAG_const_type        = 0x26,
    DW_TAG_volatile_type     = 0x35,
    DW_TAG_formal_parameter  = 0x05,
};

enum : uint32_t {
    DW_AT_name               = 0x03,
    DW_AT_low_pc             = 0x11,
    DW_AT_high_pc            = 0x12,
    DW_AT_type               = 0x49,
    DW_AT_external           = 0x3f,
    DW_AT_linkage_name       = 0x6e,
    DW_AT_MIPS_linkage_name  = 0x2007,
    DW_AT_sibling            = 0x21,
    DW_AT_declaration        = 0x3c,
    DW_AT_byte_size          = 0x0b,
    DW_AT_encoding           = 0x3e,
    DW_AT_bit_size           = 0x0d,
    DW_AT_bit_offset         = 0x0c,
    DW_AT_calling_convention = 0x36,
    DW_AT_noreturn           = 0x46,
    DW_AT_artificial         = 0x34,
    DW_AT_abstract_origin    = 0x31,
    DW_AT_specification      = 0x47,
    DW_AT_comp_dir           = 0x1b,
    DW_AT_producer           = 0x25,
    DW_AT_language           = 0x13,
};

enum : uint32_t {
    DW_FORM_addr        = 0x01, DW_FORM_block2 = 0x03, DW_FORM_block4 = 0x04,
    DW_FORM_data2       = 0x05, DW_FORM_data4 = 0x06, DW_FORM_data8 = 0x07,
    DW_FORM_string      = 0x08, DW_FORM_block  = 0x09, DW_FORM_block1 = 0x0a,
    DW_FORM_data1       = 0x0b, DW_FORM_flag   = 0x0c, DW_FORM_sdata  = 0x0d,
    DW_FORM_strp        = 0x0e, DW_FORM_udata  = 0x0f, DW_FORM_ref_addr = 0x10,
    DW_FORM_ref1        = 0x11, DW_FORM_ref2   = 0x12, DW_FORM_ref4 = 0x13,
    DW_FORM_ref8        = 0x14, DW_FORM_ref_udata = 0x15, DW_FORM_indirect = 0x16,
    DW_FORM_sec_offset  = 0x17, DW_FORM_exprloc = 0x18, DW_FORM_flag_present = 0x19,
    DW_FORM_implicit_const = 0x21,
};

struct DWARFAbbreviation {
    uint32_t code = 0; uint32_t tag = 0; bool hasChildren = false;
    std::vector<std::pair<uint32_t, uint32_t>> attributes;
};
struct SectionBuf { std::vector<uint8_t> owned; const uint8_t* data = nullptr; int size = 0;
    bool valid() const { return data != nullptr && size > 0; } };

static uint16_t r16(const uint8_t* p) { return static_cast<uint16_t>(p[0])|(static_cast<uint16_t>(p[1])<<8); }
static uint32_t r32(const uint8_t* p) { return static_cast<uint32_t>(p[0])|(static_cast<uint32_t>(p[1])<<8)|(static_cast<uint32_t>(p[2])<<16)|(static_cast<uint32_t>(p[3])<<24); }
static uint64_t r64(const uint8_t* p) { uint64_t v=0; for(int i=0;i<8;++i) v|=static_cast<uint64_t>(p[i])<<(i*8); return v; }

static void skipForm(uint32_t form, const uint8_t* data, int& pos, int maxPos, uint8_t addrSize) {
    switch(form){case DW_FORM_addr:pos+=addrSize;break;case DW_FORM_block1:if(pos<maxPos){int len=data[pos];pos+=1+len;}break;case DW_FORM_block2:if(pos+2<=maxPos){int len=r16(data+pos);pos+=2+len;}break;case DW_FORM_block4:if(pos+4<=maxPos){int len=static_cast<int>(r32(data+pos));pos+=4+len;}break;case DW_FORM_block:case DW_FORM_exprloc:{uint64_t len=readULEB128(data,pos,maxPos);pos+=static_cast<int>(len);break;}case DW_FORM_data1:case DW_FORM_ref1:case DW_FORM_flag:pos+=1;break;case DW_FORM_data2:case DW_FORM_ref2:pos+=2;break;case DW_FORM_data4:case DW_FORM_ref4:case DW_FORM_sec_offset:pos+=4;break;case DW_FORM_data8:case DW_FORM_ref8:pos+=8;break;case DW_FORM_sdata:case DW_FORM_udata:case DW_FORM_ref_udata:readULEB128(data,pos,maxPos);break;case DW_FORM_string:while(pos<maxPos&&data[pos]!=0)++pos;if(pos<maxPos)++pos;break;case DW_FORM_strp:pos+=4;break;case DW_FORM_flag_present:break;case DW_FORM_ref_addr:pos+=addrSize;break;case DW_FORM_indirect:{uint32_t f=static_cast<uint32_t>(readULEB128(data,pos,maxPos));skipForm(f,data,pos,maxPos,addrSize);break;}case DW_FORM_implicit_const:break;default:pos+=4;break;}
}

static uint64_t readFormVal(uint32_t form, const uint8_t* data, int& pos, int maxPos, uint8_t addrSize) {
    switch(form){case DW_FORM_addr:if(addrSize==8){uint64_t v=r64(data+pos);pos+=8;return v;}{uint64_t v=r32(data+pos);pos+=4;return v;}case DW_FORM_data1:case DW_FORM_ref1:case DW_FORM_flag:{uint64_t v=data[pos];pos+=1;return v;}case DW_FORM_data2:case DW_FORM_ref2:{uint64_t v=r16(data+pos);pos+=2;return v;}case DW_FORM_data4:case DW_FORM_ref4:{uint64_t v=r32(data+pos);pos+=4;return v;}case DW_FORM_data8:case DW_FORM_ref8:{uint64_t v=r64(data+pos);pos+=8;return v;}case DW_FORM_udata:case DW_FORM_ref_udata:return readULEB128(data,pos,maxPos);case DW_FORM_sdata:return static_cast<uint64_t>(readSLEB128(data,pos,maxPos));case DW_FORM_sec_offset:{uint64_t v=r32(data+pos);pos+=4;return v;}case DW_FORM_flag_present:return 1;case DW_FORM_implicit_const:return 0;default:return 0;}
}

static std::string readStr(const uint8_t* data, int& pos, int maxPos) { std::string s; while(pos<maxPos&&data[pos]!=0)s+=static_cast<char>(data[pos++]); if(pos<maxPos)++pos; return s; }
static bool readFormStr(uint32_t form, const uint8_t* data, int& pos, int maxPos, const SectionBuf& debugStr, std::string& out) {
    if(form==DW_FORM_string){out=readStr(data,pos,maxPos);return!out.empty();}if(form==DW_FORM_strp){uint64_t off=r32(data+pos);pos+=4;if(static_cast<int>(off)<debugStr.size){out=reinterpret_cast<const char*>(debugStr.data+off);return true;}}return false;
}

struct CUHeader { uint64_t offset=0,length=0,abbrevOffset=0; uint16_t version=0; uint8_t addressSize=0; int dieStart=0,dieEnd=0; };
static bool readCU(const uint8_t* data, int sz, int& pos, CUHeader& cu) {
    if(pos+4>sz)return false; cu.offset=static_cast<uint64_t>(pos); uint32_t il=r32(data+pos); pos+=4;
    if(il==0xFFFFFFFF){if(pos+8>sz)return false; cu.length=r64(data+pos); pos+=8;}else{cu.length=il;}
    if(pos+2>sz)return false; cu.version=r16(data+pos); pos+=2;
    if(cu.version>=5){if(pos+2>sz)return false;pos+=1;cu.addressSize=data[pos++];}
    if(pos+4>sz)return false; cu.abbrevOffset=r32(data+pos); pos+=4;
    if(cu.version<5){if(pos+1>sz)return false;cu.addressSize=data[pos++];}
    cu.dieStart=pos; int hs=cu.dieStart-static_cast<int>(cu.offset);
    cu.dieEnd=static_cast<int>(cu.offset)+hs+static_cast<int>(cu.length)-(il==0xFFFFFFFF?4:0);
    if(cu.dieEnd>sz)cu.dieEnd=sz; return true;
}

static bool parseAbbrev(const uint8_t* data, int sz, uint64_t off, std::unordered_map<uint32_t,DWARFAbbreviation>& t) {
    if(static_cast<int>(off)>=sz)return false; int pos=static_cast<int>(off);
    while(pos<sz){uint32_t code=static_cast<uint32_t>(readULEB128(data,pos,sz));if(code==0)break;
        DWARFAbbreviation ab;ab.code=code;ab.tag=static_cast<uint32_t>(readULEB128(data,pos,sz));
        if(pos>=sz)break;ab.hasChildren=(data[pos++]!=0);
        while(pos<sz){uint32_t a=static_cast<uint32_t>(readULEB128(data,pos,sz));uint32_t f=static_cast<uint32_t>(readULEB128(data,pos,sz));if(a==0&&f==0)break;ab.attributes.emplace_back(a,f);}
        t[code]=std::move(ab);}return true;
}

static SectionBuf loadSec(MemoryBlock* block) { SectionBuf b;if(!block)return b;Address s=block->getStart();Address e=block->getEnd();int sz=static_cast<int>(e.getOffset()-s.getOffset()+1);if(sz<=0)return b;b.owned.resize(sz);block->getBytes(s,b.owned.data(),sz);b.data=b.owned.data();b.size=sz;return b;}

static SectionBuf findSec(Memory* mem, const std::string& n) { MemoryBlock* b=mem->getBlock(n);if(!b){for(auto* bl:mem->getBlocks()){if(bl->getName().find(n)!=std::string::npos||bl->getName().find(n.substr(1))!=std::string::npos){b=bl;break;}}}return loadSec(b);}

static std::string san(const std::string& s) { std::string o;o.reserve(s.size());for(char c:s)o+=std::isalnum((unsigned char)c)||c=='_'||c==':'||c=='.'||c=='@'?c:'_';return o;}

} // anonymous namespace

DWARFAnalyzer::DWARFAnalyzer()
    : AbstractAnalyzer("DWARF", "Extracts DWARF debug info: functions, types, parameters, calling conventions.",
                       AnalyzerType::BYTE_ANALYZER) {
setDefaultEnablement(true); setPriority(AnalysisPriority::FORMAT_ANALYSIS.after()); setSupportsOneTimeAnalysis(true);
}
bool DWARFAnalyzer::canAnalyze(Program* program) const { return program != nullptr; }
bool DWARFAnalyzer::getDefaultEnablement(Program* program) const { return program != nullptr; }
void DWARFAnalyzer::registerOptions(Options&, Program*) {}
void DWARFAnalyzer::optionsChanged(Options&, Program*) {}

bool DWARFAnalyzer::added(Program* program, const AddressSetView& set,
                           TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;

    monitor->setMessage("Parsing DWARF debug info...");
    Memory* memory = program->getMemory();
    if (!memory) { Msg::info(getName(), "No memory"); return true; }

    SectionBuf debugInfo  = findSec(memory, "debug_info");
    SectionBuf debugAbbrev = findSec(memory, "debug_abbrev");
    SectionBuf debugStr   = findSec(memory, "debug_str");
    if (!debugInfo.valid()) return true;

    SymbolTable* symTable = program->getSymbolTable();
    FunctionManager* funcMgr = program->getFunctionManager();
    DataTypeManager* dtm = program->getDataTypeManager();
    auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(dtm);
    if (!symTable || !funcMgr) return true;

    int totalFuncs = 0, totalLabels = 0, sigApplied = 0;
    int pos = 0;
    std::map<uint64_t, DataType*> typeCache; // die_offset -> DataType*

    while (pos < debugInfo.size && !monitor->isCancelled()) {
        CUHeader cu;
        if (!readCU(debugInfo.data, debugInfo.size, pos, cu)) break;
        if (cu.version < 2 || cu.version > 5) { pos = cu.dieEnd; continue; }

        std::unordered_map<uint32_t, DWARFAbbreviation> abbrevs;
        if (debugAbbrev.valid()) parseAbbrev(debugAbbrev.data, debugAbbrev.size, cu.abbrevOffset, abbrevs);

        int diePos = cu.dieStart;
        struct Frame { int resume; };
        std::vector<Frame> stack;

        while (diePos < cu.dieEnd && !monitor->isCancelled()) {
            uint32_t code = static_cast<uint32_t>(readULEB128(debugInfo.data, diePos, debugInfo.size));
            if (code == 0) {
                bool popped = false;
                for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
                    if (it->resume > 0) { diePos = it->resume; it->resume = 0; popped = true; break; }
                }
                if (!popped && !stack.empty()) stack.pop_back();
                continue;
            }
            auto it = abbrevs.find(code);
            if (it == abbrevs.end()) break;
            const auto& ab = it->second;

            bool isSubprog = (ab.tag == DW_TAG_subprogram);
            bool isFormalParam = (ab.tag == DW_TAG_formal_parameter);
            bool isTypeDIE = (ab.tag == DW_TAG_base_type || ab.tag == DW_TAG_pointer_type ||
                             ab.tag == DW_TAG_structure_type || ab.tag == DW_TAG_class_type ||
                             ab.tag == DW_TAG_union_type || ab.tag == DW_TAG_enumeration_type ||
                             ab.tag == DW_TAG_typedef || ab.tag == DW_TAG_const_type);

            uint64_t typeRef = 0, byteSize = 0, encoding = 0;
            std::string attrName, linkageName, ccName;
            uint64_t lowPC = 0, highPC = 0;
            bool hasLowPC = false, isExternal = false, isDecl = false, noReturn = false;
            int attrStart = diePos;
            int savedDiePos = diePos;

            for (const auto& [attr, form] : ab.attributes) {
                if (monitor->isCancelled()) break;
                uint32_t effForm = form;
                if (form == DW_FORM_indirect) effForm = static_cast<uint32_t>(readULEB128(debugInfo.data, diePos, debugInfo.size));
                if (effForm == DW_FORM_implicit_const) { readULEB128(debugInfo.data, diePos, debugInfo.size); }

                if (isSubprog || isFormalParam || isTypeDIE) {
                    if (attr == DW_AT_name)
                        readFormStr(effForm, debugInfo.data, diePos, debugInfo.size, debugStr, attrName);
                    else if (attr == DW_AT_linkage_name || attr == DW_AT_MIPS_linkage_name)
                        readFormStr(effForm, debugInfo.data, diePos, debugInfo.size, debugStr, linkageName);
                    else if (attr == DW_AT_type)
                        typeRef = readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize);
                    else if (attr == DW_AT_low_pc) { lowPC = readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize); hasLowPC = true; }
                    else if (attr == DW_AT_high_pc) {
                        uint64_t v = readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize);
                        if (hasLowPC) highPC = (effForm == DW_FORM_addr || effForm == DW_FORM_data4 || effForm == DW_FORM_data8) ? v : lowPC + v;
                    }
                    else if (attr == DW_AT_external) isExternal = (readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize) != 0);
                    else if (attr == DW_AT_declaration) isDecl = (readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize) != 0);
                    else if (attr == DW_AT_byte_size) byteSize = readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize);
                    else if (attr == DW_AT_encoding) encoding = readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize);
                    else if (attr == DW_AT_calling_convention) ccName = std::to_string(readFormVal(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize));
                    else if (attr == DW_AT_noreturn) noReturn = true;
                    else skipForm(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize);
                } else {
                    skipForm(effForm, debugInfo.data, diePos, debugInfo.size, cu.addressSize);
                }
            }

            // Build type cache entries for type DIEs
            if (isTypeDIE && dtmImpl && typeRef == 0 && byteSize > 0) {
                uint64_t dieOffset = static_cast<uint64_t>(savedDiePos);
                if (typeCache.find(dieOffset) == typeCache.end()) {
                    DataType* dt = nullptr;
                    if (ab.tag == DW_TAG_base_type) {
                        int sz = static_cast<int>(byteSize);
                        switch (encoding) {
                            case 0x05: // DW_ATE_signed
                                if (sz == 1) dt = dtm->getDataType(CategoryPath::ROOT(), "byte");
                                else if (sz == 2) dt = dtm->getDataType(CategoryPath::ROOT(), "short");
                                else if (sz == 4) dt = dtm->getDataType(CategoryPath::ROOT(), "int");
                                else if (sz == 8) dt = dtm->getDataType(CategoryPath::ROOT(), "long");
                                else dt = dtm->getDataType(CategoryPath::ROOT(), "int");
                                break;
                            case 0x07: // DW_ATE_unsigned
                                if (sz == 1) dt = dtm->getDataType(CategoryPath::ROOT(), "byte");
                                else if (sz == 2) dt = dtm->getDataType(CategoryPath::ROOT(), "word");
                                else if (sz == 4) dt = dtm->getDataType(CategoryPath::ROOT(), "dword");
                                else if (sz == 8) dt = dtm->getDataType(CategoryPath::ROOT(), "qword");
                                else dt = dtm->getDataType(CategoryPath::ROOT(), "dword");
                                break;
                            case 0x04: // DW_ATE_float
                                dt = (sz <= 4) ? dtm->getDataType(CategoryPath::ROOT(), "float")
                                               : dtm->getDataType(CategoryPath::ROOT(), "double");
                                break;
                            case 0x02: // DW_ATE_boolean
                                dt = dtm->getDataType(CategoryPath::ROOT(), "bool"); break;
                            default: dt = dtm->getDataType(CategoryPath::ROOT(), "byte"); break;
                        }
                    } else if (ab.tag == DW_TAG_pointer_type && typeRef > 0) {
                        auto refIt = typeCache.find(typeRef);
                        DataType* target = (refIt != typeCache.end()) ? refIt->second : nullptr;
                        int ptrSz = program->getLanguage() ? program->getLanguage()->getDefaultSpace()->getAddressableUnitSize() : 8;
                        dt = new PointerDataType(target ? target : dtm->getDataType(CategoryPath::ROOT(), "void"), ptrSz, dtmImpl);
                    } else if (ab.tag == DW_TAG_typedef && typeRef > 0 && !attrName.empty()) {
                        auto refIt = typeCache.find(typeRef);
                        DataType* base = (refIt != typeCache.end()) ? refIt->second : nullptr;
                        if (base) dt = new TypedefDataType(CategoryPath::ROOT(), attrName, base, dtmImpl);
                    }
                    if (dt && (ab.tag != DW_TAG_pointer_type || dt != dtm->getDataType(CategoryPath::ROOT(), "void"))) {
                        typeCache[dieOffset] = dt;
                        if (ab.tag == DW_TAG_pointer_type || ab.tag == DW_TAG_typedef)
                            dtmImpl->addDataType(dt);
                    }
                }
            }

            // Create function with signature
            if (isSubprog && hasLowPC && lowPC != 0 && !isDecl) {
                AddressSpace* space = program->getLanguage() ? program->getLanguage()->getDefaultSpace() : nullptr;
                if (!space) continue;
                Address startAddr(space, static_cast<int64_t>(lowPC));
                if (memory->getBlock(startAddr)) {
                    std::string funcName = !linkageName.empty() ? san(linkageName) :
                                          !attrName.empty() ? san(attrName) :
                                          "dwarf_func_" + std::to_string(lowPC);
                    symTable->createLabel(startAddr, "dwarf." + funcName, SourceType::ANALYSIS);
                    ++totalLabels;

                    if (highPC > lowPC) {
                        Address endAddr(space, startAddr.getOffset() + static_cast<int64_t>(highPC - lowPC) - 1);
                        Function* f = funcMgr->createFunction(funcName, startAddr, AddressSet(startAddr, endAddr), SourceType::ANALYSIS);
                        if (f) {
                            ++totalFuncs;
                            // Set return type
                            if (typeRef > 0) {
                                auto refIt = typeCache.find(typeRef);
                                if (refIt != typeCache.end() && refIt->second) {
                                    f->setReturnType(refIt->second, SignatureSource::DWARF);
                                    ++sigApplied;
                                }
                            }
                            // Set noreturn
                            if (noReturn) f->setHasNoReturn(true, SignatureSource::DWARF);
                        }
                    }
                }
            }

            // Child processing — if subprogram has children, recurse into formal params
            if (isSubprog && ab.hasChildren && hasLowPC && lowPC != 0 && !isDecl) {
                Function* f = nullptr;
                if (program->getLanguage()) {
                    f = funcMgr->getFunctionContaining(Address(program->getLanguage()->getDefaultSpace(), static_cast<int64_t>(lowPC)));
                }
                int childDiePos = diePos;
                int paramOrdinal = 0;

                while (childDiePos < cu.dieEnd && !monitor->isCancelled()) {
                    uint32_t childCode = static_cast<uint32_t>(readULEB128(debugInfo.data, childDiePos, debugInfo.size));
                    if (childCode == 0) break;
                    auto childIt = abbrevs.find(childCode);
                    if (childIt == abbrevs.end()) break;
                    const auto& childAb = childIt->second;
                    if (childAb.tag != DW_TAG_formal_parameter && childAb.tag != DW_TAG_variable) {
                        for (const auto& [a, frm] : childAb.attributes)
                            skipForm(frm == DW_FORM_indirect ? static_cast<uint32_t>(readULEB128(debugInfo.data, childDiePos, debugInfo.size)) : frm, debugInfo.data, childDiePos, debugInfo.size, cu.addressSize);
                        if (!childAb.hasChildren) continue;
                    }
                    std::string paramName; uint64_t paramTypeRef = 0;
                    for (const auto& [a, frm] : childAb.attributes) {
                        uint32_t ef = (frm == DW_FORM_indirect) ? static_cast<uint32_t>(readULEB128(debugInfo.data, childDiePos, debugInfo.size)) : frm;
                        if (a == DW_AT_name) readFormStr(ef, debugInfo.data, childDiePos, debugInfo.size, debugStr, paramName);
                        else if (a == DW_AT_type) paramTypeRef = readFormVal(ef, debugInfo.data, childDiePos, debugInfo.size, cu.addressSize);
                        else skipForm(ef, debugInfo.data, childDiePos, debugInfo.size, cu.addressSize);
                    }
                    if (f && paramTypeRef > 0) {
                        auto refIt = typeCache.find(paramTypeRef);
                        DataType* pdt = (refIt != typeCache.end()) ? refIt->second : nullptr;
                        if (!pdt) pdt = dtm->getDataType(CategoryPath::ROOT(), "int");
                        if (paramName.empty()) paramName = "p" + std::to_string(paramOrdinal);
                        VariableStorage vs;
                        auto* param = new ParameterImpl(paramName, paramOrdinal, pdt, vs, program, SourceType::ANALYSIS);
                        f->addParameter(param, SignatureSource::DWARF);
                        ++paramOrdinal; ++sigApplied;
                    }
                    if (!childAb.hasChildren) continue;
                }
            }

            // Stack management for resume
            bool hasSibling = false;
            for (const auto& [a, frm] : ab.attributes) {
                if (a == DW_AT_sibling) { hasSibling = true; break; }
            }
            if (ab.hasChildren && !hasSibling && isSubprog) {
                // Just continue — children were already processed inline above
            } else if (ab.hasChildren) {
                int resumePos = 0;
                int peekPos = diePos;
                while (peekPos < cu.dieEnd) {
                    uint32_t nc = static_cast<uint32_t>(readULEB128(debugInfo.data, peekPos, debugInfo.size));
                    if (nc == 0) { resumePos = peekPos + 1; break; }
                    auto sit = abbrevs.find(nc);
                    if (sit == abbrevs.end()) break;
                    for (const auto& [a, frm] : sit->second.attributes)
                        skipForm(frm == DW_FORM_indirect ? static_cast<uint32_t>(readULEB128(debugInfo.data, peekPos, debugInfo.size)) : frm, debugInfo.data, peekPos, debugInfo.size, cu.addressSize);
                }
                if (resumePos > 0) stack.push_back({resumePos});
            }
        }
        pos = cu.dieEnd;
    }

    Msg::info(getName(), "DWARF: " + std::to_string(totalFuncs) + " funcs, " +
              std::to_string(totalLabels) + " labels, " + std::to_string(sigApplied) + " types applied.");
    return true;
}

} // namespace ghidra
