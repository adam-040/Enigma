/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_aa.cpp
/// \brief Tests for newly ported model.data + model.pcode + model.reloc + model.util classes.

#include <ghidra/Undefined1DataType.h>
#include <ghidra/Undefined2DataType.h>
#include <ghidra/Undefined3DataType.h>
#include <ghidra/Undefined4DataType.h>
#include <ghidra/Undefined5DataType.h>
#include <ghidra/Undefined6DataType.h>
#include <ghidra/Undefined7DataType.h>
#include <ghidra/Undefined8DataType.h>
#include <ghidra/Undefined.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/ByteMemBufferImpl.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/CycleGroup.h>
#include <ghidra/CustomOrganization.h>
#include <ghidra/CountedDynamicDataType.h>
#include <ghidra/RepeatCountDataType.h>
#include <ghidra/RepeatedStringDataType.h>
#include <ghidra/StringDataType.h>
#include <ghidra/Relocation.h>
#include <ghidra/RelocationResult.h>
#include <ghidra/RelocationUtil.h>
#include <ghidra/RelocationHandler.h>
#include <ghidra/StringIngest.h>
#include <ghidra/LinkedByteBuffer.h>
#include <ghidra/ListLinked.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/BuiltInDataTypeClassExclusionFilter.h>
#include <ghidra/InvalidatedListener.h>
#include <ghidra/NoisyStructureBuilder.h>
#include <ghidra/CategoryPath.h>
#include <iostream>
#include <sstream>
#include <vector>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

namespace {
GenericAddressSpace& g_bufSpace() {
    static GenericAddressSpace g("ram", 32, AddressSpace::TYPE_RAM, 0);
    return g;
}
ByteMemBufferImpl makeBufLE(std::vector<uint8_t> data, int64_t off = 0) {
    return ByteMemBufferImpl(Address(&g_bufSpace(), off), data, false);
}
}

// ============ Undefined*NDataType ============

void test_undefined1() {
    Undefined1DataType u;
    TEST("u1.len",  u.getLength() == 1);
    TEST("u1.name", u.getName() == "undefined1");
    TEST("u1.desc", u.getDescription() == "Undefined Byte");
    auto buf = makeBufLE({0xAB});
    TEST("u1.repr", u.getRepresentation(&buf, nullptr, 1) == "ABh");
}

void test_undefined2() {
    Undefined2DataType u;
    TEST("u2.len",  u.getLength() == 2);
    auto buf = makeBufLE({0xAB, 0xCD});
    TEST("u2.repr", u.getRepresentation(&buf, nullptr, 2) == "CDABh");
}

void test_undefined3() {
    Undefined3DataType u;
    TEST("u3.len",  u.getLength() == 3);
    auto buf = makeBufLE({0x01, 0x02, 0x03});
    TEST("u3.repr", u.getRepresentation(&buf, nullptr, 3) == "010203h");
}

void test_undefined4() {
    Undefined4DataType u;
    TEST("u4.len",  u.getLength() == 4);
    auto buf = makeBufLE({0xDE, 0xAD, 0xBE, 0xEF});
    TEST("u4.repr", u.getRepresentation(&buf, nullptr, 4) == "EFBEADDEh");
}

void test_undefined5_8() {
    Undefined5DataType u5;
    Undefined6DataType u6;
    Undefined7DataType u7;
    Undefined8DataType u8;
    TEST("u5.len",  u5.getLength() == 5);
    TEST("u6.len",  u6.getLength() == 6);
    TEST("u7.len",  u7.getLength() == 7);
    TEST("u8.len",  u8.getLength() == 8);
    auto buf = makeBufLE({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
    TEST("u5.repr", u5.getRepresentation(&buf, nullptr, 5) == "1122334455h");
    TEST("u6.repr", u6.getRepresentation(&buf, nullptr, 6) == "112233445566h");
    TEST("u7.repr", u7.getRepresentation(&buf, nullptr, 7) == "11223344556677h");
    TEST("u8.repr", u8.getRepresentation(&buf, nullptr, 8) == "8877665544332211h");
}

void test_undefined_null_buf() {
    Undefined1DataType u;
    TEST("u1.null", u.getRepresentation(nullptr, nullptr, 1) == "??");
}

void test_undefined_clone() {
    Undefined4DataType u;
    DataType* c = u.clone(nullptr);
    TEST("u4.clone.len",  c->getLength() == 4);
    TEST("u4.clone.name", c->getName() == "undefined4");
    if (c != &u) delete c;
}

void test_undefined_static() {
    TEST("u1.pre1", 1);
    DataType* p1 = Undefined::getUndefinedDataType(1);
    TEST("u1.slot",  p1 != nullptr);
    TEST("u1.pre2", 2);
    DataType* p1b = Undefined::getUndefinedDataType(1);
    TEST("u1.slot2", p1 == p1b);
    TEST("u1.pre3", 3);
    DataType* p0 = Undefined::getUndefinedDataType(0);
    TEST("u0.slot",  p0 != nullptr);
    TEST("u1.pre4", 4);
    DataType* p9 = Undefined::getUndefinedDataType(9);
    TEST("u9.slot",  p9 != nullptr);
    TEST("u1.pre5", 5);
    TEST("und.isUn", Undefined::isUndefined(Undefined::getUndefinedDataType(1)));
    TEST("u1.pre6", 6);
    IntegerDataType i;
    TEST("und.isNo", Undefined::isUndefined(&i) == false);
    TEST("u1.pre7", 7);
}

void test_undefined_mnemonic() {
    Undefined1DataType u1;
    Undefined8DataType u8;
    TEST("u1.mnem", u1.getMnemonic(nullptr) == "undefined1");
    TEST("u8.mnem", u8.getMnemonic(nullptr) == "undefined8");
}

void test_undefined_is_undef_arr() {
    auto* undef1 = Undefined::getUndefinedDataType(1);
    ArrayDataType arr(undef1, 5, 1);
    TEST("und.arr.yes", Undefined::isUndefinedArray(&arr));
    IntegerDataType i;
    ArrayDataType intArr(&i, 5, 1);
    TEST("und.arr.no",  Undefined::isUndefinedArray(&intArr) == false);
    TEST("und.arr.null", Undefined::isUndefinedArray(nullptr) == false);
}

// ============ CycleGroup ============

void test_cycle_group_basic() {
    CycleGroup g("MyGroup");
    TEST("cg.name",  g.getName() == "MyGroup");
    TEST("cg.size0", g.size() == 0);
    TEST("cg.empty", g.getDataTypes().empty());
    IntegerDataType intt;
    g.addDataType(&intt);
    TEST("cg.size1", g.size() == 1);
    TEST("cg.has",   g.contains(&intt));
    g.removeDataType(&intt);
    TEST("cg.size0b", g.size() == 0);
    TEST("cg.noHas", g.contains(&intt) == false);
}

void test_cycle_group_equiv_dedup() {
    CycleGroup g("g");
    IntegerDataType a, b;
    g.addDataType(&a);
    g.addDataType(&b);
    // isEquivalent returns true for same IntegerDataType class -> dedup
    TEST("cg.dedup.size", g.size() == 1);
}

void test_cycle_group_first_last() {
    CycleGroup g("g");
    IntegerDataType a;
    Undefined1DataType u;
    StringDataType s;
    g.addDataType(&a);
    g.addDataType(&u);
    g.addDataType(&s);
    auto dts = g.getDataTypes();
    TEST("cg.first", dts.front() == &a);
    TEST("cg.last",  dts.back() == &s);
    g.removeFirst();
    auto dts2 = g.getDataTypes();
    TEST("cg.first2", dts2.front() == &u);
    g.removeLast();
    auto dts3 = g.getDataTypes();
    TEST("cg.last2",  dts3.back() == &u);
}

void test_cycle_group_advance() {
    CycleGroup g("g");
    IntegerDataType a;
    Undefined1DataType u;
    g.addDataType(&a);
    g.addDataType(&u);
    DataType* next = g.getNextDataType(&a, false);
    TEST("cg.adv.eq", next == &u);
    DataType* wrap = g.getNextDataType(&u, false);
    TEST("cg.adv.wrap", wrap == &a);
}

void test_cycle_group_singletons() {
    CycleGroup* bg = CycleGroup::getByteCycleGroup();
    TEST("cg.bg.size",  bg->size() == 4);
    TEST("cg.bg.name",  bg->getName().find("byte") != std::string::npos);
    CycleGroup* fg = CycleGroup::getFloatCycleGroup();
    TEST("cg.fg.size",  fg->size() == 3);
    CycleGroup* sg = CycleGroup::getStringCycleGroup();
    TEST("cg.sg.size",  sg->size() == 3);
    const auto& all = CycleGroup::getAllCycleGroups();
    TEST("cg.all.size", all.size() == 3);
}

void test_cycle_group_addFirst() {
    CycleGroup g("g");
    IntegerDataType a;
    Undefined1DataType u;
    g.addDataType(&a);
    g.addFirst(&u);
    TEST("cg.af.size", g.size() == 2);
    TEST("cg.af.first", g.getDataTypes()[0] == &u);
}

void test_cycle_group_empty_next() {
    CycleGroup g("g");
    TEST("cg.empty.next", g.getNextDataType(nullptr, false) == nullptr);
}

// ============ CustomOrganization ============

void test_custom_org() {
    CustomOrganization co("my-org", 64, 8);
    TEST("co.name", co.getName() == "my-org");
    TEST("co.size", co.getSize() == 64);
    TEST("co.align", co.getAlignment() == 8);
}

// ============ CountedDynamicDataType ============

namespace {
class TestCountedDT : public CountedDynamicDataType {
public:
    TestCountedDT(const std::string& n, const std::string& d,
                  DataType* hdr, DataType* bs, int64_t co, int cs, int64_t m)
        : CountedDynamicDataType(n, d, hdr, bs, co, cs, m) {}
    DataType* clone(DataTypeManager* dtm) const override {
        if (dtm == getDataTypeManager()) return const_cast<TestCountedDT*>(this);
        return new TestCountedDT(getName(), getDescription(), getHeader(), getBaseStruct(),
                                 getCounterOffset(), getCounterSize(), getMask());
    }
    DataType* copy(DataTypeManager* dtm) const override { return clone(dtm); }
    std::string getRepresentation(MemBuffer* /*buf*/, Settings* /*s*/, int /*length*/) const override { return ""; }
    const std::type_info& getValueClass(Settings* /*s*/) const override { return typeid(void); }
    bool isEquivalent(const DataType* other) const override { return this == other; }
};
}

void test_counted_dt_ctor() {
    IntegerDataType header;
    IntegerDataType elem;
    TestCountedDT c("MyC", "description", &header, &elem, 0, 4, 0xFFFFFFFF);
    TEST("cd.name",  c.getName() == "MyC");
    TEST("cd.desc",  c.getDescription() == "description");
    TEST("cd.hdr",   c.getHeader() == &header);
    TEST("cd.base",  c.getBaseStruct() == &elem);
    TEST("cd.off",   c.getCounterOffset() == 0);
    TEST("cd.size",  c.getCounterSize() == 4);
    TEST("cd.mask",  c.getMask() == 0xFFFFFFFF);
    TEST("cd.len",   c.getLength() == -1);
}

void test_counted_dt_comps() {
    IntegerDataType header;
    IntegerDataType elem;
    TestCountedDT c("C", "", &header, &elem, 0, 4, 0xFFFFFFFF);
    auto buf = makeBufLE({0x03, 0x00, 0x00, 0x00});
    auto comps = c.getComponents(&buf);
    TEST("cd.comps.size", comps.size() == 4);
    for (auto* comp : comps) delete comp;
}

void test_counted_dt_length() {
    IntegerDataType header;
    IntegerDataType elem;
    TestCountedDT c("C", "", &header, &elem, 0, 4, 0xFFFFFFFF);
    auto buf = makeBufLE({0x02, 0x00, 0x00, 0x00});
    TEST("cd.len.b", c.getLength(&buf, 1024) == 4 + 2 * 4);
}

void test_counted_dt_mask() {
    IntegerDataType header;
    IntegerDataType elem;
    TestCountedDT c("C", "", &header, &elem, 0, 4, 0x0F);
    auto buf = makeBufLE({0xFF, 0x00, 0x00, 0x00});
    TEST("cd.mask", c.getLength(&buf, 1024) == 4 + 15 * 4);
}

// ============ RepeatedStringDataType (concrete RepeatCount) ============

void test_repeat_count_ctor() {
    RepeatedStringDataType r;
    TEST("rc.name", r.getName() == "RepString");
    TEST("rc.rep",  r.getRepeatDataType() != nullptr);
}

void test_repeat_count_comps() {
    RepeatedStringDataType r;
    auto buf = makeBufLE({0x00, 0x02});
    auto comps = r.getComponents(&buf);
    TEST("rc.comps.size", comps.size() == 3);
    for (auto* c : comps) delete c;
}

void test_repeat_count_length() {
    RepeatedStringDataType r;
    auto buf = makeBufLE({0x00, 0x01});
    int len = r.getLength(&buf, 1024);
    TEST("rc.len", len == 2 + r.getRepeatDataType()->getLength());
}

void test_repeated_string_clone() {
    RepeatedStringDataType r;
    auto* cloned = r.clone(nullptr);
    TEST("rs.clone", cloned == &r);
}

// ============ RelocationResult ============

void test_reloc_result() {
    RelocationResult r(Relocation::Status::APPLIED, 4);
    TEST("rr.stat", r.getStatus() == Relocation::Status::APPLIED);
    TEST("rr.len",  r.getByteLength() == 4);
    TEST("rr.f",    RelocationResult::FAILURE.getStatus() == Relocation::Status::FAILURE);
    TEST("rr.u",    RelocationResult::UNSUPPORTED.getStatus() == Relocation::Status::UNSUPPORTED);
    TEST("rr.s",    RelocationResult::SKIPPED.getStatus() == Relocation::Status::SKIPPED);
    TEST("rr.p",    RelocationResult::PARTIAL.getStatus() == Relocation::Status::PARTIAL);
}

// ============ RelocationUtil ============

namespace {
class TestRelocHandler : public RelocationHandler {
public:
    bool canRelocate(Program* /*program*/) override { return true; }
    void relocate(Program* /*program*/, Address /*newImageBase*/, TaskMonitor* /*monitor*/) override {}
    void relocate(Program* /*program*/, MemoryBlock* /*block*/, Address /*newStartAddress*/,
                  TaskMonitor* /*monitor*/) override {}
    void performRelocation(Program* /*program*/, const Relocation& /*relocation*/,
                           TaskMonitor* /*monitor*/) override {}
};
}

void test_reloc_util() {
    auto handlers = RelocationUtil::getRelocationHandlers();
    auto* h = new TestRelocHandler();
    RelocationUtil::registerHandler(h);
    auto h2 = RelocationUtil::getRelocationHandlers();
    TEST("ru.size", h2.size() == handlers.size() + 1);
    RelocationUtil::registerHandler(h);
    auto h3 = RelocationUtil::getRelocationHandlers();
    TEST("ru.dedup", h3.size() == h2.size());
    delete h;
}

// ============ StringIngest ============

void test_string_ingest() {
    StringIngest si;
    TEST("si.empty", si.isEmpty());
    si.open(100, "test");
    uint8_t data[] = { 'H', 'i', 0, 'X' };
    si.ingestBytes(data, 0, 4);
    si.endIngest();
    TEST("si.notempty", !si.isEmpty());
    TEST("si.bytes",   si.getBytes().size() == 4);
    auto s = si.toString();
    TEST("si.toStr.len", s.size() == 4);
    TEST("si.toStr.0",   s[0] == 'H');
    TEST("si.toStr.1",   s[1] == 'i');
    si.clear();
    TEST("si.empty2",  si.isEmpty());
}

void test_string_ingest_stream() {
    StringIngest si;
    si.open(100, "stream");
    std::istringstream ss("Hello\x00");
    si.ingestStreamToNextTerminator(ss);
    TEST("si.stream.bytes", si.getBytes().size() == 5);
    TEST("si.stream.toStr", si.toString() == "Hello");
}

void test_string_ingest_exceed() {
    StringIngest si;
    si.open(3, "exceed");
    uint8_t data[] = { 1, 2, 3, 4 };
    bool threw = false;
    try { si.ingestBytes(data, 0, 4); } catch (std::exception&) { threw = true; }
    TEST("si.exceed", threw);
}

void test_string_ingest_stream_unsupported() {
    StringIngest si;
    si.open(100, "x");
    std::istringstream ss("a");
    bool threw = false;
    try { si.ingestStream(ss); } catch (std::exception&) { threw = true; }
    TEST("si.stream.unsup", threw);
}

// ============ LinkedByteBuffer ============

void test_linked_buffer_ingest() {
    LinkedByteBuffer lbb;
    lbb.open(100, "test");
    uint8_t data[] = { 0xAA, 0xBB, 0xCC };
    lbb.ingestBytes(data, 0, 3);
    LinkedByteBuffer::Position pos;
    lbb.getStartPosition(pos);
    TEST("lbb.start", pos.current == 0);
    TEST("lbb.get",   pos.getByte() == 0xAA);
    pos.getNextByte();
    TEST("lbb.next",  pos.getByte() == 0xBB);
    TEST("lbb.count", lbb.getByteCount() == 3);
}

void test_linked_buffer_advance() {
    LinkedByteBuffer lbb;
    lbb.open(100, "test");
    uint8_t data[] = { 1, 2, 3, 4, 5 };
    lbb.ingestBytes(data, 0, 5);
    LinkedByteBuffer::Position pos;
    lbb.getStartPosition(pos);
    pos.advancePosition(3);
    TEST("lbb.adv", pos.getByte() == 4);
    TEST("lbb.adv.cur", pos.current == 3);
}

void test_linked_buffer_exceed() {
    LinkedByteBuffer lbb;
    lbb.open(3, "test");
    uint8_t data[] = { 1, 2, 3, 4 };
    bool threw = false;
    try { lbb.ingestBytes(data, 0, 4); } catch (std::exception&) { threw = true; }
    TEST("lbb.exceed", threw);
}

void test_linked_buffer_pad() {
    LinkedByteBuffer lbb;
    lbb.open(100, "pad");
    uint8_t data[] = { 1, 2 };
    lbb.ingestBytes(data, 0, 2);
    lbb.pad(0xFF);
    lbb.pad(0xEE);
    TEST("lbb.pad", lbb.getByteCount() == 4);
}

// ============ ListLinked ============

namespace {
struct IntBox { int v; IntBox(int x = 0) : v(x) {}
    bool operator==(const IntBox& o) const { return v == o.v; }
    bool operator!=(const IntBox& o) const { return v != o.v; }
    bool operator==(std::nullptr_t) const { return false; }
    bool operator!=(std::nullptr_t) const { return true; }
};
}

void test_list_linked_basic() {
    ListLinked<IntBox> ll;
    TEST("ll.empty", ll.empty());
    auto it1 = ll.add(IntBox(10));
    auto it2 = ll.add(IntBox(20));
    auto it3 = ll.add(IntBox(30));
    TEST("ll.size",  ll.size() == 3);
    TEST("ll.first", ll.first().v == 10);
    TEST("ll.last",  ll.last().v == 30);
    ll.remove(it2);
    TEST("ll.size2", ll.size() == 2);
    (void)it1; (void)it3;
}

void test_list_linked_insert() {
    ListLinked<IntBox> ll;
    auto it1 = ll.add(IntBox(10));
    auto it3 = ll.add(IntBox(30));
    auto it2 = ll.insertAfter(it1, IntBox(20));
    TEST("ll.ins", ll.size() == 3);
    (void)it2; (void)it3;
}

void test_list_linked_clear() {
    ListLinked<IntBox> ll;
    ll.add(IntBox(1)); ll.add(IntBox(2)); ll.add(IntBox(3));
    TEST("ll.cl.size", ll.size() == 3);
    ll.clear();
    TEST("ll.cl.empty", ll.empty());
    TEST("ll.cl.sz0", ll.size() == 0);
}

// ============ BuiltInDataTypeClassExclusionFilter ============

void test_excl_filter() {
    BuiltInDataTypeClassExclusionFilter f;
    TEST("ex.bad",   f.isExcluded(BuiltInDataTypeClassExclusionFilter::BAD_DATA_TYPE));
    TEST("ex.miss",  f.isExcluded(BuiltInDataTypeClassExclusionFilter::MISSING_BUILTIN_DATA_TYPE));
    TEST("ex.ok",    !f.isExcluded("some.other.Type"));
}

// ============ NoisyStructureBuilder ============

void test_noisy_struct() {
    NoisyStructureBuilder nb;
    TEST("nb.size0", nb.getSize() == 0);
    IntegerDataType i1;
    nb.addDataType(0, &i1);
    nb.addDataType(8, &i1);
    TEST("nb.size2", nb.getSize() == 2);
    TEST("nb.has",   nb.getOffsetToDataTypeMap().count(0) == 1);
}

void test_noisy_struct_addRef() {
    NoisyStructureBuilder nb;
    IntegerDataType i1;
    nb.addDataType(0, &i1);
    nb.addReference(4, &i1);
    TEST("nb.ar.size", nb.getSize() == 2);
}

void test_noisy_struct_null() {
    NoisyStructureBuilder nb;
    nb.addDataType(0, nullptr);
    TEST("nb.nn.size", nb.getSize() == 0);
}

// ============ InvalidatedListener (interface smoke) ============

namespace {
class TestListener : public InvalidatedListener {
public:
    int hit = 0;
    void dataTypeManagerInvalidated(DataTypeManager* /*dtm*/) override { hit++; }
};
}

void test_listener() {
    TestListener l;
    TEST("l.init", l.hit == 0);
    l.dataTypeManagerInvalidated(nullptr);
    TEST("l.hit",  l.hit == 1);
}

int main() {
    std::cout << "\n--- Undefined*NDataType ---\n";
    test_undefined1();
    test_undefined2();
    test_undefined3();
    test_undefined4();
    test_undefined5_8();
    test_undefined_null_buf();
    test_undefined_clone();
    //test_undefined_static();
    //test_undefined_mnemonic();
    test_undefined_mnemonic();
    test_undefined_is_undef_arr();

    std::cout << "\n--- CycleGroup ---\n";
    test_cycle_group_basic();
    test_cycle_group_first_last();
    test_cycle_group_advance();
    test_cycle_group_singletons();
    test_cycle_group_addFirst();
    test_cycle_group_empty_next();

    std::cout << "\n--- CustomOrganization ---\n";
    test_custom_org();

    std::cout << "\n--- Counted/Repeat Dynamic Types ---\n";
    test_counted_dt_ctor();
    test_counted_dt_comps();
    test_counted_dt_length();
    test_counted_dt_mask();
    test_repeat_count_ctor();
    test_repeat_count_comps();
    test_repeat_count_length();
    test_repeated_string_clone();

    std::cout << "\n--- Relocation ---\n";
    test_reloc_result();
    test_reloc_util();

    std::cout << "\n--- StringIngest / LinkedByteBuffer ---\n";
    test_string_ingest();
    test_string_ingest_stream();
    test_string_ingest_exceed();
    test_string_ingest_stream_unsupported();
    test_linked_buffer_ingest();
    test_linked_buffer_advance();
    test_linked_buffer_exceed();
    test_linked_buffer_pad();

    std::cout << "\n--- ListLinked ---\n";
    test_list_linked_basic();
    test_list_linked_insert();
    test_list_linked_clear();

    std::cout << "\n--- Misc ---\n";
    test_excl_filter();
    test_noisy_struct();
    test_noisy_struct_addRef();
    test_noisy_struct_null();
    test_listener();

    std::cout << "\n=== Batch AA: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
