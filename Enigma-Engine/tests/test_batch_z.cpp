/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_z.cpp
/// \brief Tests for Batch Z: CodeUnit, Instruction, Data, Listing, Register,
///        Scalar, FlowOverride, MemReferenceImpl, Reference interface coverage
///        for the program.listing and program.symbol packages.
#include <ghidra/CodeUnit.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/Listing.h>
#include <ghidra/Register.h>
#include <ghidra/Scalar.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/RefType.h>
#include <ghidra/Reference.h>
#include <ghidra/MemReferenceImpl.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/CharDataType.h>
#include <ghidra/WideChar32DataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/AbstractDataType.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/Varnode.h>
#include <ghidra/PcodeOp.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// Simple test DataType subclass for "unicode" naming
class UnicodeDataType : public AbstractDataType {
public:
    UnicodeDataType() : AbstractDataType(CategoryPath::ROOT(), "unicode32", nullptr) {}
    int getLength() const override { return 4; }
};

// Shared test fixture
struct ZFixture {
    GenericAddressSpace ram{"ram", 32, AddressSpace::TYPE_RAM, 0};
    GenericAddressSpace stack{"stack", 32, AddressSpace::TYPE_STACK, 1};
    ProgramDB prog;

    ZFixture() : prog("z_test", nullptr, nullptr) {
        if (auto* af = dynamic_cast<ProgramAddressFactory*>(prog.getAddressFactory())) {
            af->addAddressSpace(&ram);
            af->setDefaultSpace(&ram);
            af->addAddressSpace(&stack);
            af->setStackSpace(&stack);
        }
    }

    Address addr(uint32_t off) { return Address(&ram, off); }
};

} // namespace

// ============ CodeUnit base class ============

namespace {
class TestCodeUnit : public CodeUnit {
public:
    TestCodeUnit() = default;
    TestCodeUnit(Program* p, Address a, DataType* d) : CodeUnit(p, a, d) {}
    int getLength() const override { return dataType_ ? dataType_->getLength() : 1; }
    std::string toString() const override {
        return address_.toString();
    }
};
} // namespace

void test_codeunit_default_ctor() {
    TestCodeUnit cu;
    TEST("cu.dflt.prog",   cu.getProgram() == nullptr);
    TEST("cu.dflt.addr",   cu.getAddress() == Address());
    TEST("cu.dflt.dt",     cu.getDataType() == nullptr);
    TEST("cu.dflt.cmt",    cu.getComment().empty());
    TEST("cu.dflt.plate",  cu.getPlateComment().empty());
    TEST("cu.dflt.pre",    cu.getPreComment().empty());
    TEST("cu.dflt.post",   cu.getPostComment().empty());
    TEST("cu.dflt.noRefs", cu.hasReferences() == false);
    TEST("cu.dflt.len",    cu.getLength() == 1);
    TEST("cu.dflt.toStr",  !cu.toString().empty());
}

void test_codeunit_setters() {
    ZFixture f;
    TestCodeUnit cu(&f.prog, f.addr(0x100), nullptr);
    cu.setComment("comment");
    cu.setPlateComment("plate");
    cu.setPreComment("pre");
    cu.setPostComment("post");
    TEST("cu.set.cmt",  cu.getComment() == "comment");
    TEST("cu.set.plate",cu.getPlateComment() == "plate");
    TEST("cu.set.pre",  cu.getPreComment() == "pre");
    TEST("cu.set.post", cu.getPostComment() == "post");
}

void test_codeunit_setAddress() {
    ZFixture f;
    TestCodeUnit cu(&f.prog, f.addr(0x100), nullptr);
    cu.setAddress(f.addr(0x200));
    TEST("cu.setAddr", cu.getAddress() == f.addr(0x200));
}

void test_codeunit_setDataType() {
    ZFixture f;
    TestCodeUnit cu(&f.prog, f.addr(0x100), nullptr);
    IntegerDataType idt;
    cu.setDataType(&idt);
    TEST("cu.setDT", cu.getDataType() == &idt);
}

void test_codeunit_getMaxAddress() {
    ZFixture f;
    DWordDataType dword;
    TestCodeUnit cu(&f.prog, f.addr(0x100), &dword);
    Address mx = cu.getMaxAddress();
    TEST("cu.maxAddr.eq", mx == f.addr(0x103));
}

void test_codeunit_getMaxAddress_no_dt() {
    ZFixture f;
    TestCodeUnit cu(&f.prog, f.addr(0x100), nullptr);
    Address mx = cu.getMaxAddress();
    TEST("cu.maxAddr.noDT", mx == f.addr(0x100));
}

void test_codeunit_references() {
    ZFixture f;
    TestCodeUnit cu(&f.prog, f.addr(0x100), nullptr);
    TEST("cu.refs.empty",   cu.getReferencesFrom().empty());
    TEST("cu.refsTo.empty", cu.getReferencesTo().empty());
    TEST("cu.refs.none",    cu.hasReferences() == false);
    Reference* fakeFrom = reinterpret_cast<Reference*>(0x1000);
    Reference* fakeTo   = reinterpret_cast<Reference*>(0x2000);
    cu.addReferenceFrom(fakeFrom);
    cu.addReferenceTo(fakeTo);
    TEST("cu.refs.from",   cu.getReferencesFrom().size() == 1);
    TEST("cu.refs.to",     cu.getReferencesTo().size() == 1);
    TEST("cu.refs.has",    cu.hasReferences() == true);
}

// ============ Instruction ============

void test_instruction_default_ctor() {
    Instruction inst;
    TEST("inst.dflt.mnem",  inst.getMnemonicString().empty());
    TEST("inst.dflt.len",   inst.getLength() == 0);
    TEST("inst.dflt.flow",  inst.getFlowType() == nullptr);
    TEST("inst.dflt.ops",   inst.getNumOperands() == 0);
    TEST("inst.dflt.noPC",  inst.hasPcode() == false);
    TEST("inst.dflt.fo",    inst.getFlowOverride() == FlowOverride::NONE);
    TEST("inst.dflt.noOvr", inst.isLengthOverridden() == false);
    TEST("inst.dflt.noDS",  inst.isInDelaySlot() == false);
}

void test_instruction_ctor() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    TEST("inst.ctor.prog",   inst.getProgram() == &f.prog);
    TEST("inst.ctor.addr",   inst.getAddress() == f.addr(0x100));
    TEST("inst.ctor.mnem",   inst.getMnemonicString() == "MOV");
    TEST("inst.ctor.len",    inst.getLength() == 3);
    TEST("inst.ctor.ops",    inst.getNumOperands() == 0);
    TEST("inst.ctor.minAd",  inst.getMinAddress() == f.addr(0x100));
    TEST("inst.ctor.defFTO", inst.getDefaultFallThroughOffset() == 3);
}

void test_instruction_set_mnemonic() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    inst.setMnemonic("ADD");
    TEST("inst.setMnem", inst.getMnemonicString() == "ADD");
}

void test_instruction_flow_type() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "JMP", 3);
    FlowType ft(RefType::__UNCONDITIONAL_JUMP, "JUMP", true, false, false, true, false, false, false);
    inst.setFlowType(&ft);
    TEST("inst.flowType", inst.getFlowType() == &ft);
}

void test_instruction_operands() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    inst.setOperand(0, "RAX");
    inst.setOperand(1, "RBX");
    inst.setOperand(3, "RDX");
    TEST("inst.ops.count", inst.getNumOperands() == 4);
    TEST("inst.ops.0",     inst.getOperandRefString(0) == "RAX");
    TEST("inst.ops.1",     inst.getOperandRefString(1) == "RBX");
    TEST("inst.ops.2",     inst.getOperandRefString(2).empty());
    TEST("inst.ops.3",     inst.getOperandRefString(3) == "RDX");
    TEST("inst.ops.oob",   inst.getOperandRefString(99).empty());
}

void test_instruction_inputs_results() {
    ZFixture f;
    GenericAddressSpace regsp{"reg", 32, AddressSpace::TYPE_REGISTER, 2};
    Address regA(&regsp, 0);
    Address regB(&regsp, 4);
    Register rA("RAX", "64-bit general", regA, 8, 0, 64, false, 0);
    Register rB("RBX", "64-bit general", regB, 8, 0, 64, false, 0);
    Instruction inst(&f.prog, f.addr(0x100), "ADD", 3);
    inst.addInputObject(&rA);
    inst.addResultObject(&rB);
    TEST("inst.inp.size",  inst.getInputObjects().size() == 1);
    TEST("inst.inp.first", inst.getInputObjects()[0] == &rA);
    TEST("inst.res.size",  inst.getResultObjects().size() == 1);
    TEST("inst.res.first", inst.getResultObjects()[0] == &rB);
}

void test_instruction_scalars() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    Scalar s1(32, 0x42);
    Scalar s2(32, 0x10);
    inst.addScalar(&s1);
    inst.addScalar(&s2);
    TEST("inst.scal.size",   inst.getScalars().size() == 2);
    TEST("inst.scal.first",  inst.getScalars()[0] == &s1);
    TEST("inst.scal.second", inst.getScalars()[1] == &s2);
}

void test_instruction_pcode() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "ADD", 3);
    TEST("inst.pc.none", inst.hasPcode() == false);
    PcodeOp op(f.addr(0x100), 0, PcodeOp::INT_ADD);
    inst.addPcode(&op);
    TEST("inst.pc.has",  inst.hasPcode() == true);
    TEST("inst.pc.size", inst.getPcode().size() == 1);
    TEST("inst.pc.first",inst.getPcode()[0] == &op);
}

void test_instruction_flows() {
    ZFixture f;
    GenericAddressSpace sp("ram2", 32, AddressSpace::TYPE_RAM, 3);
    Address tgt(&sp, 0x200);
    Varnode vn(tgt, 4);
    Instruction inst(&f.prog, f.addr(0x100), "JMP", 3);
    inst.addFlow(&vn);
    TEST("inst.flows.size", inst.getFlows().size() == 1);
    TEST("inst.flows.first",inst.getFlows()[0] == &vn);
}

void test_instruction_flow_override() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "RET", 1);
    inst.setFlowOverride(FlowOverride::RETURN);
    TEST("inst.fo.set", inst.getFlowOverride() == FlowOverride::RETURN);
    inst.setFlowOverride(FlowOverride::BRANCH);
    TEST("inst.fo.br",  inst.getFlowOverride() == FlowOverride::BRANCH);
}

void test_instruction_fallthrough() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    Address def = inst.getFallThrough();
    TEST("inst.ft.def.eq", def == f.addr(0x103));
    inst.setFallThrough(f.addr(0x500));
    TEST("inst.ft.set",    inst.getFallThrough() == f.addr(0x500));
    Address def2 = inst.getDefaultFallThrough();
    TEST("inst.defFT",     def2 == f.addr(0x103));
}

void test_instruction_length_overridden() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    TEST("inst.lenOvr.f", inst.isLengthOverridden() == false);
    inst.setLengthOverridden(true);
    TEST("inst.lenOvr.t", inst.isLengthOverridden() == true);
}

void test_instruction_operand_scalars() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    Scalar s1(32, 1), s2(32, 2);
    inst.addOperandScalar(0, &s1);
    inst.addOperandScalar(0, &s2);
    auto s = inst.getOperandScalars(0);
    TEST("inst.opScal.cnt", s.size() == 2);
    TEST("inst.opScal.0",   s[0] == &s1);
    auto s3 = inst.getOperandScalars(1);
    TEST("inst.opScal.empty", s3.empty());
    auto sNeg = inst.getOperandScalars(-1);
    TEST("inst.opScal.neg", sNeg.empty());
}

void test_instruction_operand_registers() {
    ZFixture f;
    GenericAddressSpace regsp{"reg", 32, AddressSpace::TYPE_REGISTER, 2};
    Address regA(&regsp, 0);
    Register rA("RAX", "desc", regA, 8, 0, 64, false, 0);
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    inst.addOperandRegister(0, &rA);
    auto r = inst.getOperandRegisters(0);
    TEST("inst.opReg.cnt", r.size() == 1);
    TEST("inst.opReg.0",   r[0] == &rA);
    auto empty = inst.getOperandRegisters(99);
    TEST("inst.opReg.empty", empty.empty());
}

void test_instruction_toString() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    inst.setOperand(0, "RAX");
    inst.setOperand(1, "RBX");
    std::string s = inst.toString();
    TEST("inst.toStr.has",     !s.empty());
    TEST("inst.toStr.mnem",    s.find("MOV") != std::string::npos);
    TEST("inst.toStr.op0",     s.find("RAX") != std::string::npos);
    TEST("inst.toStr.op1",     s.find("RBX") != std::string::npos);
}

void test_instruction_label() {
    ZFixture f;
    Instruction inst(&f.prog, f.addr(0x100), "CALL", 3);
    TEST("inst.lbl.eq", inst.getDefaultLabelRepresentation() == "CALL");
}

void test_instruction_getNext_no_prog() {
    Instruction inst;
    TEST("inst.nextNull", inst.getNext() == nullptr);
}

void test_instruction_getFallFrom_no_prog() {
    Instruction inst;
    Address fa = inst.getFallFrom();
    TEST("inst.fallFrom.noProg", fa == Address::NO_ADDRESS);
}

void test_instruction_getFallThrough_no_addr() {
    Instruction inst;
    Address ft = inst.getFallThrough();
    TEST("inst.ft.noAddr", ft == Address::NO_ADDRESS);
}

// ============ Data ============

void test_data_default_ctor() {
    Data d;
    TEST("d.dflt.len",   d.getLength() == 0);
    TEST("d.dflt.dt",    d.getDataType() == nullptr);
    TEST("d.dflt.bdt",   d.getBaseDataType() == nullptr);
    TEST("d.dflt.comps", d.getNumComponents() == 0);
    TEST("d.dflt.comp",  d.getComponent(0) == nullptr);
    TEST("d.dflt.par",   d.getParent() == nullptr);
    TEST("d.dflt.off",   d.getComponentOffset() == 0);
    TEST("d.dflt.und",   d.isDefined() == false);
}

void test_data_ctor() {
    ZFixture f;
    DWordDataType dword;
    Data d(&f.prog, f.addr(0x100), &dword, 4);
    TEST("d.ctor.prog", d.getProgram() == &f.prog);
    TEST("d.ctor.addr", d.getAddress() == f.addr(0x100));
    TEST("d.ctor.dt",   d.getDataType() == &dword);
    TEST("d.ctor.bdt",  d.getBaseDataType() == &dword);
    TEST("d.ctor.len",  d.getLength() == 4);
    TEST("d.ctor.def",  d.isDefined() == true);
}

void test_data_components() {
    ZFixture f;
    DWordDataType dword;
    Data parent(&f.prog, f.addr(0x100), &dword, 8);
    Data c1(&f.prog, f.addr(0x100), &dword, 4);
    Data c2(&f.prog, f.addr(0x104), &dword, 4);
    parent.addComponent(&c1);
    parent.addComponent(&c2);
    TEST("d.comp.cnt",   parent.getNumComponents() == 2);
    TEST("d.comp.0",     parent.getComponent(0) == &c1);
    TEST("d.comp.1",     parent.getComponent(1) == &c2);
    TEST("d.comp.oob",   parent.getComponent(99) == nullptr);
    TEST("d.comp.par0",  c1.getParent() == &parent);
    TEST("d.comp.par1",  c2.getParent() == &parent);
}

void test_data_component_offset() {
    ZFixture f;
    DWordDataType dword;
    Data d(&f.prog, f.addr(0x100), &dword, 4);
    d.setComponentOffset(8);
    TEST("d.compOff.set", d.getComponentOffset() == 8);
}

void test_data_isPointer() {
    ZFixture f;
    IntegerDataType intt;
    PointerDataType p(&intt, 4);
    Data d(&f.prog, f.addr(0x100), &p, 4);
    TEST("d.isPtr", d.isPointer());
}

void test_data_isString_char() {
    ZFixture f;
    CharDataType chart;
    Data d(&f.prog, f.addr(0x200), &chart, 1);
    TEST("d.isStr.char", d.isString());
}

void test_data_isString_false() {
    ZFixture f;
    DWordDataType dword;
    Data d(&f.prog, f.addr(0x100), &dword, 4);
    TEST("d.isStr.false", d.isString() == false);
}

void test_data_isUnicode() {
    ZFixture f;
    WideChar32DataType wct;
    Data d(&f.prog, f.addr(0x100), &wct, 4);
    TEST("d.isUni.t",  d.isUnicode() == false);
    TEST("d.isUni.f.ne", d.getDataType()->getName() != "unicode");
}

void test_data_isArray() {
    ZFixture f;
    IntegerDataType intt;
    ArrayDataType adt(&intt, 10);
    Data d(&f.prog, f.addr(0x100), &adt, 40);
    TEST("d.isArr", d.isArray());
}

void test_data_isStructure() {
    ZFixture f;
    StructureDataType sdt("struct Foo", 8);
    Data d(&f.prog, f.addr(0x100), &sdt, 8);
    TEST("d.isStruct", d.isStructure());
    TEST("d.isUnion.f", d.isUnion() == false);
}

void test_data_isUnion() {
    ZFixture f;
    UnionDataType udt("union Bar");
    Data d(&f.prog, f.addr(0x100), &udt, 4);
    TEST("d.isUnion", d.isUnion());
    TEST("d.isStr.f",  d.isStructure() == false);
}

void test_data_toString() {
    ZFixture f;
    DWordDataType dword;
    Data d(&f.prog, f.addr(0x100), &dword, 4);
    std::string s = d.toString();
    TEST("d.toStr.has",     !s.empty());
    TEST("d.toStr.hasAddr", s.find("100") != std::string::npos);
    TEST("d.toStr.hasLen",  s.find("4") != std::string::npos);
}

void test_data_getDefaultLabelRepresentation() {
    ZFixture f;
    DWordDataType dword;
    Data d(&f.prog, f.addr(0x100), &dword, 4);
    TEST("d.lbl.eq", d.getDefaultLabelRepresentation() == "dword");
}

void test_data_getPrimitiveAt() {
    ZFixture f;
    DWordDataType dword;
    Data d(&f.prog, f.addr(0x100), &dword, 8);
    Data* p0 = d.getPrimitiveAt(0);
    Data* p3 = d.getPrimitiveAt(3);
    Data* p7 = d.getPrimitiveAt(7);
    Data* p8 = d.getPrimitiveAt(8);
    Data* pN = d.getPrimitiveAt(-1);
    TEST("d.primAt.0",   p0 == &d);
    TEST("d.primAt.3",   p3 == &d);
    TEST("d.primAt.7",   p7 == &d);
    TEST("d.primAt.oob", p8 == nullptr);
    TEST("d.primAt.neg", pN == nullptr);
}

// ============ Listing ============

void test_listing_default_ctor() {
    Listing listing;
    TEST("list.dflt.prog", listing.getProgram() == nullptr);
    TEST("list.dflt.icnt", listing.getInstructionCount() == 0);
    TEST("list.dflt.dcnt", listing.getDataCount() == 0);
}

void test_listing_ctor_with_prog() {
    ZFixture f;
    Listing listing(&f.prog);
    TEST("list.ctor.prog", listing.getProgram() == &f.prog);
}

void test_listing_add_get_instruction() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    listing.addInstruction(&inst);
    TEST("list.addInst.count", listing.getInstructionCount() == 1);
    TEST("list.addInst.get",   listing.getInstructionAt(f.addr(0x100)) == &inst);
    TEST("list.addInst.miss",  listing.getInstructionAt(f.addr(0x999)) == nullptr);
}

void test_listing_add_data() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    Data data(&f.prog, f.addr(0x200), &dword, 4);
    listing.addData(&data);
    TEST("list.addData.count", listing.getDataCount() == 1);
    TEST("list.addData.get",   listing.getDataAt(f.addr(0x200)) == &data);
    TEST("list.addData.miss",  listing.getDataAt(f.addr(0x999)) == nullptr);
}

void test_listing_create_data() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    Data* d = listing.createData(f.addr(0x300), &dword);
    TEST("list.createData.notNull", d != nullptr);
    TEST("list.createData.addr",    d->getAddress() == f.addr(0x300));
    TEST("list.createData.len",     d->getLength() == 4);
    TEST("list.createData.dt",      d->getDataType() == &dword);
    TEST("list.createData.count",  listing.getDataCount() == 1);
}

void test_listing_create_data_default_length() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    Data* d = listing.createData(f.addr(0x300), &dword, -1);
    TEST("list.createData.dfltLen", d->getLength() == 4);
}

void test_listing_create_data_null_dt() {
    ZFixture f;
    Listing listing(&f.prog);
    Data* d = listing.createData(f.addr(0x300), nullptr);
    TEST("list.createData.nullDT", d == nullptr);
}

void test_listing_create_data_overwrite() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    listing.createData(f.addr(0x300), &dword);
    Data* d2 = listing.createData(f.addr(0x300), &dword);
    TEST("list.createData.overwrite", d2 == nullptr);
    TEST("list.createData.count",    listing.getDataCount() == 1);
}

void test_listing_remove_instruction() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    listing.addInstruction(&inst);
    TEST("list.remInst.pre",  listing.getInstructionAt(f.addr(0x100)) == &inst);
    listing.removeInstruction(f.addr(0x100));
    TEST("list.remInst.post", listing.getInstructionAt(f.addr(0x100)) == nullptr);
    TEST("list.remInst.cnt",  listing.getInstructionCount() == 0);
}

void test_listing_remove_data() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    Data data(&f.prog, f.addr(0x200), &dword, 4);
    listing.addData(&data);
    TEST("list.remData.pre",  listing.getDataAt(f.addr(0x200)) == &data);
    listing.removeData(f.addr(0x200));
    TEST("list.remData.post", listing.getDataAt(f.addr(0x200)) == nullptr);
    TEST("list.remData.cnt",  listing.getDataCount() == 0);
}

void test_listing_getInstructionContaining() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    listing.addInstruction(&inst);
    TEST("list.instCont.eq",  listing.getInstructionContaining(f.addr(0x100)) == &inst);
    TEST("list.instCont.miss",listing.getInstructionContaining(f.addr(0x999)) == nullptr);
}

void test_listing_getDataContaining() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    Data data(&f.prog, f.addr(0x200), &dword, 4);
    listing.addData(&data);
    TEST("list.dataCont.eq",  listing.getDataContaining(f.addr(0x200)) == &data);
    TEST("list.dataCont.miss",listing.getDataContaining(f.addr(0x999)) == nullptr);
}

void test_listing_getInstructionAfter() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction i1(&f.prog, f.addr(0x100), "MOV", 3);
    Instruction i2(&f.prog, f.addr(0x200), "ADD", 3);
    Instruction i3(&f.prog, f.addr(0x300), "JMP", 3);
    listing.addInstruction(&i1);
    listing.addInstruction(&i2);
    listing.addInstruction(&i3);
    TEST("list.instAfter.100", listing.getInstructionAfter(f.addr(0x100)) == &i2);
    TEST("list.instAfter.150", listing.getInstructionAfter(f.addr(0x150)) == &i2);
    TEST("list.instAfter.250", listing.getInstructionAfter(f.addr(0x250)) == &i3);
    TEST("list.instAfter.300", listing.getInstructionAfter(f.addr(0x300)) == nullptr);
}

void test_listing_getDefinedDataContaining() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    Data data(&f.prog, f.addr(0x200), &dword, 4);
    listing.addData(&data);
    TEST("list.defDataCont.eq",  listing.getDefinedDataContaining(f.addr(0x200)) == &data);
    TEST("list.defDataCont.miss",listing.getDefinedDataContaining(f.addr(0x999)) == nullptr);
}

void test_listing_getCodeUnitAt() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    DWordDataType dword;
    Data data(&f.prog, f.addr(0x200), &dword, 4);
    listing.addInstruction(&inst);
    listing.addData(&data);
    CodeUnit* cu1 = listing.getCodeUnitAt(f.addr(0x100));
    CodeUnit* cu2 = listing.getCodeUnitAt(f.addr(0x200));
    CodeUnit* cu3 = listing.getCodeUnitAt(f.addr(0x999));
    TEST("list.cuAt.inst",  cu1 == &inst);
    TEST("list.cuAt.data",  cu2 == &data);
    TEST("list.cuAt.null",  cu3 == nullptr);
}

void test_listing_getCodeUnitContaining() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    DWordDataType dword;
    Data data(&f.prog, f.addr(0x200), &dword, 4);
    listing.addInstruction(&inst);
    listing.addData(&data);
    CodeUnit* cu1 = listing.getCodeUnitContaining(f.addr(0x100));
    CodeUnit* cu2 = listing.getCodeUnitContaining(f.addr(0x200));
    TEST("list.cuCont.inst", cu1 == &inst);
    TEST("list.cuCont.data", cu2 == &data);
}

void test_listing_isUndefined() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction inst(&f.prog, f.addr(0x100), "MOV", 3);
    listing.addInstruction(&inst);
    TEST("list.undef.yes", listing.isUndefined(f.addr(0x999)) == true);
    TEST("list.undef.no",  listing.isUndefined(f.addr(0x100)) == false);
}

void test_listing_getInstructions_set() {
    ZFixture f;
    Listing listing(&f.prog);
    Instruction i1(&f.prog, f.addr(0x100), "MOV", 3);
    Instruction i2(&f.prog, f.addr(0x200), "ADD", 3);
    Instruction i3(&f.prog, f.addr(0x300), "JMP", 3);
    listing.addInstruction(&i1);
    listing.addInstruction(&i2);
    listing.addInstruction(&i3);
    AddressSet set(f.addr(0x100), f.addr(0x200));
    auto insns = listing.getInstructions(set);
    TEST("list.getInsts.cnt", insns.size() == 2);
    bool has1 = false, has2 = false, has3 = false;
    for (auto* i : insns) {
        if (i == &i1) has1 = true;
        if (i == &i2) has2 = true;
        if (i == &i3) has3 = true;
    }
    TEST("list.getInsts.1", has1);
    TEST("list.getInsts.2", has2);
    TEST("list.getInsts.3.notIn", !has3);
}

void test_listing_getData_set() {
    ZFixture f;
    Listing listing(&f.prog);
    DWordDataType dword;
    Data d1(&f.prog, f.addr(0x100), &dword, 4);
    Data d2(&f.prog, f.addr(0x200), &dword, 4);
    listing.addData(&d1);
    listing.addData(&d2);
    AddressSet set(f.addr(0x100), f.addr(0x200));
    auto datas = listing.getData(set);
    TEST("list.getData.cnt", datas.size() == 2);
}

// ============ Scalar ============

void test_scalar_default() {
    Scalar s;
    TEST("sc.dflt.bits", s.getBitLength() == 0);
    TEST("sc.dflt.unsigned", s.getUnsignedValue() == 0);
    TEST("sc.dflt.signed", s.getSignedValue() == 0);
    TEST("sc.dflt.isSigned", s.isSigned() == false);
    TEST("sc.dflt.isHex", s.isHex() == false);
}

void test_scalar_unsigned() {
    Scalar s(32, 0x7EADBEEF, false);
    TEST("sc.uns.bits",   s.getBitLength() == 32);
    TEST("sc.uns.value",  s.getUnsignedValue() == 0x7EADBEEF);
    TEST("sc.uns.signed", s.getSignedValue() == static_cast<int64_t>(0x7EADBEEF));
    TEST("sc.uns.isS",    s.isSigned() == false);
}

void test_scalar_signed_positive() {
    Scalar s(32, 100, true);
    TEST("sc.sgnp.value", s.getSignedValue() == 100);
    TEST("sc.sgnp.isS",   s.isSigned() == true);
}

void test_scalar_signed_negative() {
    Scalar s(8, 0xFF, true);
    TEST("sc.sgnn.value", s.getSignedValue() == -1);
}

void test_scalar_set_signed() {
    Scalar s(32, 1);
    s.setSigned(true);
    TEST("sc.setS", s.isSigned() == true);
}

void test_scalar_hex() {
    Scalar s(32, 0x100, false, true);
    TEST("sc.hex.isH", s.isHex() == true);
    std::string str = s.toString();
    TEST("sc.hex.has0x", str.find("0x") != std::string::npos);
}

void test_scalar_decimal_toString() {
    Scalar s(32, 42, false, false);
    std::string str = s.toString();
    TEST("sc.dec.has42", str.find("42") != std::string::npos);
    TEST("sc.dec.no0x",  str.find("0x") == std::string::npos);
}

void test_scalar_equality() {
    Scalar a(32, 0x42);
    Scalar b(32, 0x42);
    Scalar c(32, 0x43);
    TEST("sc.eq.same",  a == b);
    TEST("sc.eq.diff",  !(a == c));
    TEST("sc.neq.diff", a != c);
}

// ============ Register ============

void test_register_ctor() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register r("RAX", "64-bit general", regAddr, 8, 0, 64, false, 0);
    TEST("reg.ctor.name", r.getName() == "RAX");
    TEST("reg.ctor.desc", r.getDescription() == "64-bit general");
    TEST("reg.ctor.bytes",r.getNumBytes() == 8);
    TEST("reg.ctor.bits", r.getBitLength() == 64);
    TEST("reg.ctor.le",   r.isBigEndian() == false);
    TEST("reg.ctor.lsb",  r.getLeastSignificantBit() == 0);
    TEST("reg.ctor.minB", r.getMinimumByteSize() == 8);
    TEST("reg.ctor.base", r.isBaseRegister() == true);
    TEST("reg.ctor.flags",r.getTypeFlags() == 0);
}

void test_register_aliases() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register r("EAX", "32-bit", regAddr, 4, 0, 32, false, 0);
    r.addAlias("AX");
    r.addAlias("AL");
    r.addAlias("AH");
    TEST("reg.alias.cnt",  r.getAliases().size() == 3);
    TEST("reg.alias.hasAX",r.getAliases().count("AX") == 1);
    TEST("reg.alias.hasAL",r.getAliases().count("AL") == 1);
    r.removeAlias("AX");
    TEST("reg.alias.rmCnt", r.getAliases().size() == 2);
    TEST("reg.alias.noAX",  r.getAliases().count("AX") == 0);
}

void test_register_type_flags() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register r("PC", "program counter", regAddr, 8, 0, 64, false, Register::TYPE_PC);
    TEST("reg.flag.PC",    r.isProgramCounter());
    TEST("reg.flag.notFP", r.isDefaultFramePointer() == false);
    Register r2("FP", "frame pointer", regAddr, 8, 0, 64, false, Register::TYPE_FP);
    TEST("reg.flag.FP",    r2.isDefaultFramePointer());
    Register r3("RSP", "stack", regAddr, 8, 0, 64, false, Register::TYPE_SP | Register::TYPE_DOES_NOT_FOLLOW_FLOW);
    TEST("reg.flag.SP",    r3.followsFlow() == false);
    Register r4("HIDDEN", "hidden reg", regAddr, 8, 0, 64, false, Register::TYPE_HIDDEN);
    TEST("reg.flag.hidden",r4.isHidden());
    Register r5("Z", "zero", regAddr, 8, 0, 64, false, Register::TYPE_ZERO);
    TEST("reg.flag.zero",  r5.isZero());
    Register r6("VEC", "vector", regAddr, 16, 0, 128, false, Register::TYPE_VECTOR);
    TEST("reg.flag.vec",   r6.isVectorRegister());
}

void test_register_equality() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register r1("RAX", "desc", regAddr, 8, 0, 64, false, 0);
    Register r2("RAX", "other", regAddr, 8, 0, 64, false, 0);
    Register r3("RBX", "desc", regAddr, 8, 0, 64, false, 0);
    TEST("reg.eq.same",  r1 == r2);
    TEST("reg.eq.diff",  !(r1 == r3));
    TEST("reg.neq.diff", r1 != r3);
}

void test_register_setParent() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register parent("RAX", "64-bit", regAddr, 8, 0, 64, false, 0);
    Register child("EAX", "32-bit", regAddr, 4, 0, 32, false, 0);
    child.setParent(&parent);
    TEST("reg.par.set", child.getParentRegister() == &parent);
}

void test_register_setChildRegisters() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register parent("RAX", "64-bit", regAddr, 8, 0, 64, false, 0);
    Register c1("EAX", "32-bit", regAddr, 4, 0, 32, false, 0);
    Register c2("AX", "16-bit", regAddr, 2, 0, 16, false, 0);
    parent.setChildRegisters({&c1, &c2});
    TEST("reg.child.cnt",  parent.getChildRegisters().size() == 2);
    TEST("reg.child.hasC1", parent.getChildRegisters()[0] == &c1);
    TEST("reg.child.hasC2", parent.getChildRegisters()[1] == &c2);
    TEST("reg.child.hasKids",parent.hasChildren());
}

void test_register_rename() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register r("OLD", "desc", regAddr, 8, 0, 64, false, 0);
    r.rename("NEW");
    TEST("reg.rename", r.getName() == "NEW");
}

void test_register_toString() {
    ZFixture f;
    Address regAddr(&f.ram, 0x100);
    Register r("RAX", "desc", regAddr, 8, 0, 64, false, 0);
    std::string s = r.toString();
    TEST("reg.toStr.has", !s.empty());
}

void test_register_compareTo() {
    ZFixture f;
    Address regAddr1(&f.ram, 0x100);
    Address regAddr2(&f.ram, 0x200);
    Register r1("AAA", "d", regAddr1, 8, 0, 64, false, 0);
    Register r2("ZZZ", "d", regAddr2, 8, 0, 64, false, 0);
    TEST("reg.cmp.lt", r1 < r2);
    TEST("reg.cmp.gt.f", !(r2 < r1));
    TEST("reg.cmp.eq.f", !(r1 < r1));
}

// ============ FlowOverride ============

void test_flow_override_enum() {
    TEST("fo.NONE",     FlowOverride::NONE == static_cast<FlowOverride>(0));
    TEST("fo.BRANCH",   FlowOverride::BRANCH == static_cast<FlowOverride>(1));
    TEST("fo.CALL",     FlowOverride::CALL == static_cast<FlowOverride>(2));
    TEST("fo.CALLRET",  FlowOverride::CALL_RETURN == static_cast<FlowOverride>(3));
    TEST("fo.RETURN",   FlowOverride::RETURN == static_cast<FlowOverride>(4));
}

void test_flow_override_toString() {
    std::string s = flowOverrideToString(FlowOverride::BRANCH);
    TEST("fo.toStr", !s.empty());
    std::string s2 = flowOverrideToString(FlowOverride::RETURN);
    TEST("fo.toStr.ret", !s2.empty());
    std::string s3 = flowOverrideToString(FlowOverride::CALL);
    TEST("fo.toStr.call", !s3.empty());
}

void test_flow_override_stringTo() {
    FlowOverride fo = stringToFlowOverride("branch");
    TEST("fo.strTo.br", fo == FlowOverride::BRANCH);
    FlowOverride fo2 = stringToFlowOverride("return");
    TEST("fo.strTo.ret", fo2 == FlowOverride::RETURN);
    FlowOverride fo3 = stringToFlowOverride("call");
    TEST("fo.strTo.call", fo3 == FlowOverride::CALL);
    FlowOverride fo4 = stringToFlowOverride("callreturn");
    TEST("fo.strTo.cr", fo4 == FlowOverride::CALL_RETURN);
    FlowOverride fo5 = stringToFlowOverride("none");
    TEST("fo.strTo.none", fo5 == FlowOverride::NONE);
}

// ============ MemReferenceImpl ============

void test_memref_ctor() {
    ZFixture f;
    MemReferenceImpl ref(f.addr(0x100), f.addr(0x200), &RefTypes::READ);
    TEST("mr.from",   ref.getFromAddress() == f.addr(0x100));
    TEST("mr.to",     ref.getToAddress() == f.addr(0x200));
    TEST("mr.type",   ref.getReferenceType() == &RefTypes::READ);
    TEST("mr.opIdx",  ref.getOperandIndex() == Reference::NOOperandIndex);
    TEST("mr.prim",   ref.isPrimary());
    TEST("mr.src",    ref.getSource() == SourceType::DEFAULT);
    TEST("mr.mem",    ref.isMemoryReference());
    TEST("mr.notReg", ref.isRegisterReference() == false);
    TEST("mr.notStk", ref.isStackReference() == false);
    TEST("mr.notExt", ref.isExternalReference() == false);
    TEST("mr.notEP",  ref.isEntryPointReference() == false);
    TEST("mr.notOff", ref.isOffsetReference() == false);
    TEST("mr.notShf", ref.isShiftedReference() == false);
    TEST("mr.notOp",  ref.isOperandReference() == false);
    TEST("mr.mnem",   ref.isMnemonicReference());
}

void test_memref_operand() {
    ZFixture f;
    MemReferenceImpl ref(f.addr(0x100), f.addr(0x200), &RefTypes::READ,
                         SourceType::USER_DEFINED, 0, true, 42);
    TEST("mr.op.opIdx",   ref.getOperandIndex() == 0);
    TEST("mr.op.isOpRef", ref.isOperandReference());
    TEST("mr.op.notMem",  ref.isMnemonicReference() == false);
    TEST("mr.op.src",     ref.getSource() == SourceType::USER_DEFINED);
    TEST("mr.op.id",      ref.getID() == 42);
}

void test_memref_setSource() {
    ZFixture f;
    MemReferenceImpl ref(f.addr(0x100), f.addr(0x200), &RefTypes::READ);
    ref.setSource(SourceType::IMPORTED);
    TEST("mr.setSrc", ref.getSource() == SourceType::IMPORTED);
}

void test_memref_toString() {
    ZFixture f;
    MemReferenceImpl ref(f.addr(0x100), f.addr(0x200), &RefTypes::READ);
    std::string s = ref.toString();
    TEST("memref.toString.nonempty", !s.empty());
    TEST("memref.toString.hasArrow", s.find("->") != std::string::npos);
    TEST("memref.toString.hasType",  s.find("READ") != std::string::npos);
}

void test_memref_equality() {
    ZFixture f;
    MemReferenceImpl a(f.addr(0x100), f.addr(0x200), &RefTypes::READ);
    MemReferenceImpl b(f.addr(0x100), f.addr(0x200), &RefTypes::READ);
    MemReferenceImpl c(f.addr(0x100), f.addr(0x300), &RefTypes::READ);
    MemReferenceImpl d(f.addr(0x100), f.addr(0x200), &RefTypes::WRITE);
    TEST("mr.eq.same",   a == b);
    TEST("mr.eq.diffAddr",   !(a == c));
    TEST("mr.eq.diffType",   !(a == d));
    TEST("mr.neq.diff",  a != c);
}

// ============ Reference interface verification ============

void test_reference_interface_constants() {
    TEST("ref.MNEMONIC",        Reference::MNEMONIC == -1);
    TEST("ref.OTHER",           Reference::OTHER == -2);
    TEST("ref.NOOperandIndex",  Reference::NOOperandIndex == -1);
    TEST("ref.NO_MNEMONIC",     Reference::NO_MNEMONIC_INDEX == -1);
    TEST("ref.FALLBACK",        Reference::FALLBACK_REF_ID == -1);
}

void test_reference_interface_polymorphism() {
    ZFixture f;
    MemReferenceImpl impl(f.addr(0x100), f.addr(0x200), &RefTypes::READ);
    Reference* iface = static_cast<Reference*>(&impl);
    TEST("ref.iface.toAddr",  iface->getFromAddress() == f.addr(0x100));
    TEST("ref.iface.fromAddr", iface->getToAddress() == f.addr(0x200));
    TEST("ref.iface.type",  iface->getReferenceType() == &RefTypes::READ);
    TEST("ref.iface.id",    iface->getID() == -1);
    TEST("ref.iface.eq",    *iface == *iface);
}

int main() {
    std::cout << "\n--- CodeUnit ---\n";
    test_codeunit_default_ctor();
    test_codeunit_setters();
    test_codeunit_setAddress();
    test_codeunit_setDataType();
    test_codeunit_getMaxAddress();
    test_codeunit_getMaxAddress_no_dt();
    test_codeunit_references();

    std::cout << "\n--- Instruction ---\n";
    test_instruction_default_ctor();
    test_instruction_ctor();
    test_instruction_set_mnemonic();
    test_instruction_flow_type();
    test_instruction_operands();
    test_instruction_inputs_results();
    test_instruction_scalars();
    test_instruction_pcode();
    test_instruction_flows();
    test_instruction_flow_override();
    test_instruction_fallthrough();
    test_instruction_length_overridden();
    test_instruction_operand_scalars();
    test_instruction_operand_registers();
    test_instruction_toString();
    test_instruction_label();
    test_instruction_getNext_no_prog();
    test_instruction_getFallFrom_no_prog();
    test_instruction_getFallThrough_no_addr();

    std::cout << "\n--- Data ---\n";
    test_data_default_ctor();
    test_data_ctor();
    test_data_components();
    test_data_component_offset();
    test_data_isPointer();
    test_data_isString_char();
    test_data_isString_false();
    test_data_isUnicode();
    test_data_isArray();
    test_data_isStructure();
    test_data_isUnion();
    test_data_toString();
    test_data_getDefaultLabelRepresentation();
    test_data_getPrimitiveAt();

    std::cout << "\n--- Listing ---\n";
    test_listing_default_ctor();
    test_listing_ctor_with_prog();
    test_listing_add_get_instruction();
    test_listing_add_data();
    test_listing_create_data();
    test_listing_create_data_default_length();
    test_listing_create_data_null_dt();
    test_listing_create_data_overwrite();
    test_listing_remove_instruction();
    test_listing_remove_data();
    test_listing_getInstructionContaining();
    test_listing_getDataContaining();
    test_listing_getInstructionAfter();
    test_listing_getDefinedDataContaining();
    test_listing_getCodeUnitAt();
    test_listing_getCodeUnitContaining();
    test_listing_isUndefined();
    test_listing_getInstructions_set();
    test_listing_getData_set();

    std::cout << "\n--- Scalar ---\n";
    test_scalar_default();
    test_scalar_unsigned();
    test_scalar_signed_positive();
    test_scalar_signed_negative();
    test_scalar_set_signed();
    test_scalar_hex();
    test_scalar_decimal_toString();
    test_scalar_equality();

    std::cout << "\n--- Register ---\n";
    test_register_ctor();
    test_register_aliases();
    test_register_type_flags();
    test_register_equality();
    test_register_setParent();
    test_register_setChildRegisters();
    test_register_rename();
    test_register_toString();
    test_register_compareTo();

    std::cout << "\n--- FlowOverride ---\n";
    test_flow_override_enum();
    test_flow_override_toString();
    test_flow_override_stringTo();

    std::cout << "\n--- MemReferenceImpl + Reference ---\n";
    test_memref_ctor();
    test_memref_operand();
    test_memref_setSource();
    test_memref_toString();
    test_memref_equality();
    test_reference_interface_constants();
    test_reference_interface_polymorphism();

    std::cout << "\n=== Batch Z: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
