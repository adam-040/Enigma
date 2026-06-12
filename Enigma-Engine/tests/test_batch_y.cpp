/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_y.cpp
/// \brief Tests for Batch Y: PropertyMapManager + IntRangeMap + AddressSetPropertyMap
///        (interface verification + concrete impl coverage), plus ManagerDB lifecycle
///        coverage on PropertyMapManagerImpl.
#include <ghidra/PropertyMapManager.h>
#include <ghidra/PropertyMapManagerImpl.h>
#include <ghidra/IntRangeMap.h>
#include <ghidra/AddressSetPropertyMap.h>
#include <ghidra/ManagerDB.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/AddressRange.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/TaskMonitor.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// Shared test fixture: in-memory ProgramDB with ram space, plus 2 empty TaskMonitor stubs
struct YFixture {
    GenericAddressSpace ram{"ram", 32, AddressSpace::TYPE_RAM, 0};
    ProgramDB prog;
    StubTaskMonitor mon;

    YFixture() : prog("y_test", nullptr, nullptr) {
        if (auto* af = dynamic_cast<ProgramAddressFactory*>(prog.getAddressFactory())) {
            af->addAddressSpace(&ram);
            af->setDefaultSpace(&ram);
        }
    }

    Address addr(uint32_t off) { return Address(&ram, off); }
};

} // namespace

// ============ AddressSetPropertyMap interface verification ============

void test_asp_interface_contract() {
    // The interface must be a base class; concrete impl is a subclass
    AddressSetPropertyMapImpl impl("foo");
    AddressSetPropertyMap* iface = &impl;
    TEST("asp.iface.name",     iface->getName() == "foo");
}

void test_asp_basic_add_remove() {
    YFixture f;
    AddressSetPropertyMapImpl impl("map1");
    TEST("asp.empty.contains",  impl.contains(f.addr(0x100)) == false);
    impl.add(f.addr(0x100), f.addr(0x200));
    TEST("asp.add.contains.lo", impl.contains(f.addr(0x100)) == true);
    TEST("asp.add.contains.mid",impl.contains(f.addr(0x150)) == true);
    TEST("asp.add.contains.hi", impl.contains(f.addr(0x200)) == true);
    TEST("asp.add.contains.out",impl.contains(f.addr(0x201)) == false);
    impl.remove(f.addr(0x150), f.addr(0x180));
    TEST("asp.rem.contains.lo", impl.contains(f.addr(0x100)) == true);
    TEST("asp.rem.contains.removed", impl.contains(f.addr(0x150)) == false);
    TEST("asp.rem.contains.hi", impl.contains(f.addr(0x200)) == true);
}

void test_asp_add_set() {
    YFixture f;
    AddressSetPropertyMapImpl impl("map2");
    impl.add(f.addr(0x100), f.addr(0x200));
    AddressSet other;
    other.add(f.addr(0x300), f.addr(0x400));
    impl.add(other);
    TEST("asp.setAdd.contains.a", impl.contains(f.addr(0x100)) == true);
    TEST("asp.setAdd.contains.b", impl.contains(f.addr(0x300)) == true);
    impl.set(other);
    TEST("asp.set.onlyA",        impl.contains(f.addr(0x100)) == false);
    TEST("asp.set.onlyB",        impl.contains(f.addr(0x300)) == true);
}

void test_asp_remove_set() {
    YFixture f;
    AddressSetPropertyMapImpl impl("map3");
    impl.add(f.addr(0x100), f.addr(0x300));
    AddressSet toRemove;
    toRemove.add(f.addr(0x150), f.addr(0x200));
    impl.remove(toRemove);
    TEST("asp.remSet.lo",        impl.contains(f.addr(0x100)) == true);
    TEST("asp.remSet.removed",   impl.contains(f.addr(0x150)) == false);
    TEST("asp.remSet.hi",        impl.contains(f.addr(0x300)) == true);
}

void test_asp_get_address_set() {
    YFixture f;
    AddressSetPropertyMapImpl impl("map4");
    impl.add(f.addr(0x100), f.addr(0x200));
    impl.add(f.addr(0x300), f.addr(0x400));
    AddressSet result = impl.getAddressSet();
    TEST("asp.getSet.sizeA",  result.contains(f.addr(0x100)));
    TEST("asp.getSet.sizeB",  result.contains(f.addr(0x300)));
    TEST("asp.getSet.empty",  result.contains(f.addr(0x250)) == false);
}

void test_asp_get_addresses() {
    YFixture f;
    AddressSetPropertyMapImpl impl("map5");
    impl.add(f.addr(0x100), f.addr(0x103));
    auto* it = impl.getAddresses();
    int count = 0;
    bool saw100 = false, saw101 = false, saw102 = false, saw103 = false;
    while (it->hasNext()) {
        Address a = it->next();
        if (a == f.addr(0x100)) saw100 = true;
        if (a == f.addr(0x101)) saw101 = true;
        if (a == f.addr(0x102)) saw102 = true;
        if (a == f.addr(0x103)) saw103 = true;
        count++;
    }
    delete it;
    TEST("asp.getAddr.count",  count == 4);
    TEST("asp.getAddr.100",    saw100);
    TEST("asp.getAddr.101",    saw101);
    TEST("asp.getAddr.102",    saw102);
    TEST("asp.getAddr.103",    saw103);
}

void test_asp_get_address_ranges() {
    YFixture f;
    AddressSetPropertyMapImpl impl("map6");
    impl.add(f.addr(0x100), f.addr(0x200));
    impl.add(f.addr(0x300), f.addr(0x400));
    auto* it = impl.getAddressRanges();
    int n = 0;
    bool sawRange100 = false, sawRange300 = false;
    while (it->hasNext()) {
        AddressRange r = it->next();
        if (r.getMinAddress() == f.addr(0x100)) sawRange100 = true;
        if (r.getMinAddress() == f.addr(0x300)) sawRange300 = true;
        n++;
    }
    delete it;
    TEST("asp.getRanges.count",    n == 2);
    TEST("asp.getRanges.range100", sawRange100);
    TEST("asp.getRanges.range300", sawRange300);
}

void test_asp_clear() {
    YFixture f;
    AddressSetPropertyMapImpl impl("map7");
    impl.add(f.addr(0x100), f.addr(0x200));
    TEST("asp.clear.pre",    impl.contains(f.addr(0x100)) == true);
    impl.clear();
    TEST("asp.clear.post",   impl.contains(f.addr(0x100)) == false);
    TEST("asp.clear.empty",  impl.getAddressSet().isEmpty());
}

// ============ IntRangeMap interface + concrete impl ============

void test_irm_basic() {
    YFixture f;
    IntRangeMapImpl impl("m1");
    TEST("irm.name",     impl.getName() == "m1");
    TEST("irm.zero",     impl.getValue(f.addr(0x999)) == 0);
}

void test_irm_set_get() {
    YFixture f;
    IntRangeMapImpl impl("m2");
    impl.setValue(f.addr(0x100), f.addr(0x200), 0x42);
    TEST("irm.set.inRange",   impl.getValue(f.addr(0x150)) == 0x42);
    TEST("irm.set.lo",        impl.getValue(f.addr(0x100)) == 0x42);
    TEST("irm.set.hi",        impl.getValue(f.addr(0x200)) == 0x42);
    TEST("irm.set.out",       impl.getValue(f.addr(0x201)) == 0);
}

void test_irm_multi_range() {
    YFixture f;
    IntRangeMapImpl impl("m3");
    impl.setValue(f.addr(0x100), f.addr(0x1FF), 1);
    impl.setValue(f.addr(0x200), f.addr(0x2FF), 2);
    impl.setValue(f.addr(0x300), f.addr(0x3FF), 3);
    TEST("irm.multi.r1",  impl.getValue(f.addr(0x150)) == 1);
    TEST("irm.multi.r2",  impl.getValue(f.addr(0x250)) == 2);
    TEST("irm.multi.r3",  impl.getValue(f.addr(0x350)) == 3);
    TEST("irm.multi.gap", impl.getValue(f.addr(0x400)) == 0);
}

void test_irm_clear_value() {
    YFixture f;
    IntRangeMapImpl impl("m4");
    impl.setValue(f.addr(0x100), f.addr(0x200), 0x99);
    impl.clearValue(f.addr(0x100), f.addr(0x200));
    TEST("irm.clear.inRange", impl.getValue(f.addr(0x150)) == 0);
}

void test_irm_overwrite() {
    YFixture f;
    IntRangeMapImpl impl("m5");
    impl.setValue(f.addr(0x100), f.addr(0x200), 1);
    impl.setValue(f.addr(0x100), f.addr(0x200), 2);
    TEST("irm.overwrite.first",  impl.getValue(f.addr(0x150)) == 1);
    TEST("irm.overwrite.lo",     impl.getValue(f.addr(0x100)) == 1);
    TEST("irm.overwrite.hi",     impl.getValue(f.addr(0x200)) == 1);
    TEST("irm.overwrite.size",   impl.getRanges().size() == 2);
}

void test_irm_negative_values() {
    YFixture f;
    IntRangeMapImpl impl("m6");
    impl.setValue(f.addr(0x100), f.addr(0x200), -1);
    TEST("irm.neg", impl.getValue(f.addr(0x150)) == -1);
}

// ============ PropertyMapManager interface + concrete impl ============

void test_pmm_default_ctor() {
    PropertyMapManagerImpl pmm;
    TEST("pmm.default.name", pmm.getName() == "PropertyMapManager");
    TEST("pmm.default.count", pmm.getNumEntries() == 0);
    TEST("pmm.default.rev",   pmm.getRevision() == 0);
    TEST("pmm.default.afg",   pmm.getAddressSetPropertyMap("nope") == nullptr);
    TEST("pmm.default.ifg",   pmm.getIntRangeMap("nope") == nullptr);
}

void test_pmm_create_and_get_addrset() {
    PropertyMapManagerImpl pmm;
    auto* m = pmm.createAddressSetPropertyMap("MyMap");
    TEST("pmm.asp.created",  m != nullptr);
    TEST("pmm.asp.name",     m->getName() == "MyMap");
    TEST("pmm.asp.get",      pmm.getAddressSetPropertyMap("MyMap") == m);
    TEST("pmm.asp.count",    pmm.getNumEntries() == 1);
}

void test_pmm_create_and_get_intrange() {
    PropertyMapManagerImpl pmm;
    auto* m = pmm.createIntRangeMap("StackDepth");
    TEST("pmm.irm.created",  m != nullptr);
    TEST("pmm.irm.name",     m->getName() == "StackDepth");
    TEST("pmm.irm.get",      pmm.getIntRangeMap("StackDepth") == m);
    TEST("pmm.irm.count",    pmm.getNumEntries() == 1);
}

void test_pmm_multi_create() {
    PropertyMapManagerImpl pmm;
    pmm.createAddressSetPropertyMap("A");
    pmm.createAddressSetPropertyMap("B");
    pmm.createIntRangeMap("C");
    pmm.createIntRangeMap("D");
    TEST("pmm.multi.count", pmm.getNumEntries() == 4);
    TEST("pmm.multi.A",     pmm.getAddressSetPropertyMap("A") != nullptr);
    TEST("pmm.multi.B",     pmm.getAddressSetPropertyMap("B") != nullptr);
    TEST("pmm.multi.C",     pmm.getIntRangeMap("C") != nullptr);
    TEST("pmm.multi.D",     pmm.getIntRangeMap("D") != nullptr);
    TEST("pmm.multi.A_is_B",pmm.getAddressSetPropertyMap("A") != pmm.getAddressSetPropertyMap("B"));
}

void test_pmm_delete_addrset() {
    PropertyMapManagerImpl pmm;
    auto* m = pmm.createAddressSetPropertyMap("X");
    TEST("pmm.delA.pre",  pmm.getAddressSetPropertyMap("X") == m);
    pmm.deleteAddressSetPropertyMap("X");
    TEST("pmm.delA.post", pmm.getAddressSetPropertyMap("X") == nullptr);
    TEST("pmm.delA.count",pmm.getNumEntries() == 0);
}

void test_pmm_delete_intrange() {
    PropertyMapManagerImpl pmm;
    auto* m = pmm.createIntRangeMap("Y");
    TEST("pmm.delI.pre",  pmm.getIntRangeMap("Y") == m);
    pmm.deleteIntRangeMap("Y");
    TEST("pmm.delI.post", pmm.getIntRangeMap("Y") == nullptr);
    TEST("pmm.delI.count",pmm.getNumEntries() == 0);
}

void test_pmm_delete_missing() {
    PropertyMapManagerImpl pmm;
    pmm.deleteAddressSetPropertyMap("Nope");
    pmm.deleteIntRangeMap("Nope");
    TEST("pmm.delMissing.noThrow", pmm.getNumEntries() == 0);
}

void test_pmm_recreate_same_name() {
    PropertyMapManagerImpl pmm;
    auto* a = pmm.createAddressSetPropertyMap("K");
    auto* b = pmm.createAddressSetPropertyMap("K");
    TEST("pmm.recreate.replace", pmm.getAddressSetPropertyMap("K") == b);
    TEST("pmm.recreate.count",   pmm.getNumEntries() == 1);
}

// ============ ManagerDB lifecycle on PropertyMapManagerImpl ============

void test_pmm_set_program() {
    YFixture f;
    PropertyMapManagerImpl pmm;
    pmm.setProgram(&f.prog);
    TEST("pmm.setProg.name", pmm.getName() == "PropertyMapManager");
}

void test_pmm_program_ready() {
    YFixture f;
    PropertyMapManagerImpl pmm;
    pmm.setProgram(&f.prog);
    pmm.programReady(0, 0, &f.mon);
    TEST("pmm.progReady.noThrow", pmm.getName() == "PropertyMapManager");
}

void test_pmm_revision() {
    PropertyMapManagerImpl pmm;
    TEST("pmm.rev.init", pmm.getRevision() == 0);
    pmm.setRevision(42);
    TEST("pmm.rev.set",  pmm.getRevision() == 42);
    pmm.setRevision(-1);
    TEST("pmm.rev.neg",  pmm.getRevision() == -1);
}

void test_pmm_clear_cache_all() {
    PropertyMapManagerImpl pmm;
    pmm.createAddressSetPropertyMap("A");
    pmm.createIntRangeMap("B");
    TEST("pmm.clr.pre",  pmm.getNumEntries() == 2);
    pmm.clearCache(true);
    TEST("pmm.clr.all",  pmm.getNumEntries() == 0);
    TEST("pmm.clr.A",    pmm.getAddressSetPropertyMap("A") == nullptr);
    TEST("pmm.clr.B",    pmm.getIntRangeMap("B") == nullptr);
}

void test_pmm_clear_cache_partial() {
    PropertyMapManagerImpl pmm;
    auto* a = pmm.createAddressSetPropertyMap("A");
    pmm.clearCache(false);
    TEST("pmm.clr.partial.A",   pmm.getAddressSetPropertyMap("A") == a);
    TEST("pmm.clr.partial.cnt",  pmm.getNumEntries() == 1);
}

void test_pmm_invalidate_cache() {
    PropertyMapManagerImpl pmm;
    pmm.createAddressSetPropertyMap("A");
    pmm.invalidateCache(true);
    TEST("pmm.invalidate",   pmm.getAddressSetPropertyMap("A") == nullptr);
}

void test_pmm_delete_address_range() {
    YFixture f;
    PropertyMapManagerImpl pmm;
    pmm.deleteAddressRange(f.addr(0x100), f.addr(0x200), &f.mon);
    TEST("pmm.delAddr.noThrow", pmm.getName() == "PropertyMapManager");
}

void test_pmm_move_address_range() {
    YFixture f;
    PropertyMapManagerImpl pmm;
    pmm.moveAddressRange(f.addr(0x100), f.addr(0x200), 0x100, &f.mon);
    TEST("pmm.movAddr.noThrow", pmm.getName() == "PropertyMapManager");
}

// ============ AddressSet + AddressIterator cross-check ============

void test_address_set_basic() {
    YFixture f;
    AddressSet s;
    TEST("aset.init.empty",  s.isEmpty());
    s.add(f.addr(0x100), f.addr(0x200));
    TEST("aset.add.contains",s.contains(f.addr(0x150)));
    TEST("aset.add.containsE",s.contains(f.addr(0x100)));
    TEST("aset.add.containsL",s.contains(f.addr(0x200)));
    TEST("aset.add.notOob",  s.contains(f.addr(0x201)) == false);
}

void test_address_set_from_ctor() {
    YFixture f;
    AddressSet s(f.addr(0x300), f.addr(0x400));
    TEST("aset.ctor.contains", s.contains(f.addr(0x350)));
    TEST("aset.ctor.notEmpty", !s.isEmpty());
}

void test_address_set_min_max() {
    YFixture f;
    AddressSet s;
    s.add(f.addr(0x500), f.addr(0x600));
    s.add(f.addr(0x300), f.addr(0x400));
    TEST("aset.min",   s.getMinAddress() == f.addr(0x300));
    TEST("aset.max",   s.getMaxAddress() == f.addr(0x600));
    TEST("aset.ranges",s.getNumAddressRanges() == 2);
}

void test_address_set_clear() {
    YFixture f;
    AddressSet s(f.addr(0x100), f.addr(0x200));
    s.clear();
    TEST("aset.clear.empty",   s.isEmpty());
    TEST("aset.clear.contains",s.contains(f.addr(0x150)) == false);
}

void test_address_set_union() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x200));
    AddressSet b(f.addr(0x300), f.addr(0x400));
    AddressSet u = a.unionSet(b);
    TEST("aset.union.a",  u.contains(f.addr(0x150)));
    TEST("aset.union.b",  u.contains(f.addr(0x350)));
    TEST("aset.union.gap",u.contains(f.addr(0x250)) == false);
}

void test_address_set_intersect() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x300));
    AddressSet b(f.addr(0x200), f.addr(0x400));
    AddressSet i = a.intersect(b);
    TEST("aset.isec.lo", i.contains(f.addr(0x250)));
    TEST("aset.isec.notA",i.contains(f.addr(0x150)) == false);
    TEST("aset.isec.notB",i.contains(f.addr(0x350)) == false);
}

void test_address_set_subtract() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x300));
    AddressSet b(f.addr(0x200), f.addr(0x250));
    AddressSet r = a.subtract(b);
    TEST("aset.sub.pre", r.contains(f.addr(0x150)));
    TEST("aset.sub.removed", r.contains(f.addr(0x220)) == false);
    TEST("aset.sub.post", r.contains(f.addr(0x280)));
}

void test_address_set_xor() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x300));
    AddressSet b(f.addr(0x200), f.addr(0x400));
    AddressSet x = a.xorSet(b);
    TEST("aset.xor.pre", x.contains(f.addr(0x150)));
    TEST("aset.xor.overlapNot", x.contains(f.addr(0x250)) == false);
    TEST("aset.xor.post", x.contains(f.addr(0x350)));
}

void test_address_set_equality() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x200));
    AddressSet b(f.addr(0x100), f.addr(0x200));
    AddressSet c(f.addr(0x300), f.addr(0x400));
    TEST("aset.eq.same",     a == b);
    TEST("aset.eq.diff",     !(a == c));
    TEST("aset.neq.diff",    a != c);
    TEST("aset.neq.same",    !(a != b));
}

void test_address_set_hasSameAddresses() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x200));
    AddressSet b(f.addr(0x100), f.addr(0x200));
    AddressSet c(f.addr(0x300), f.addr(0x400));
    TEST("aset.sameAddr.same",  a.hasSameAddresses(b));
    TEST("aset.sameAddr.diff",  !a.hasSameAddresses(c));
}

void test_address_set_count() {
    YFixture f;
    AddressSet s;
    TEST("aset.cnt.init", s.getNumAddresses() == 0);
    s.add(f.addr(0x100), f.addr(0x103));
    TEST("aset.cnt.four", s.getNumAddresses() == 4);
}

void test_address_set_print() {
    YFixture f;
    AddressSet s(f.addr(0x100), f.addr(0x200));
    std::string p = s.printRanges();
    TEST("aset.print.nonempty", !p.empty());
}

void test_address_set_toList() {
    YFixture f;
    AddressSet s;
    s.add(f.addr(0x100), f.addr(0x200));
    s.add(f.addr(0x300), f.addr(0x400));
    auto ranges = s.toList();
    TEST("aset.list.size",   ranges.size() == 2);
    TEST("aset.list.first",  ranges[0].getMinAddress() == f.addr(0x100));
    TEST("aset.list.second", ranges[1].getMinAddress() == f.addr(0x300));
}

void test_address_set_getRangeContaining() {
    YFixture f;
    AddressSet s;
    s.add(f.addr(0x100), f.addr(0x200));
    s.add(f.addr(0x300), f.addr(0x400));
    AddressRange r = s.getRangeContaining(f.addr(0x150));
    TEST("aset.rngCtn.lo",  r.getMinAddress() == f.addr(0x100));
    TEST("aset.rngCtn.hi",  r.getMaxAddress() == f.addr(0x200));
    AddressRange r2 = s.getRangeContaining(f.addr(0x350));
    TEST("aset.rngCtn.b.lo",r2.getMinAddress() == f.addr(0x300));
}

void test_address_set_first_last_range() {
    YFixture f;
    AddressSet s;
    s.add(f.addr(0x300), f.addr(0x400));
    s.add(f.addr(0x100), f.addr(0x200));
    TEST("aset.firstRng.min", s.getFirstRange().getMinAddress() == f.addr(0x100));
    TEST("aset.lastRng.max",  s.getLastRange().getMaxAddress() == f.addr(0x400));
}

void test_address_set_findFirstCommon() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x300));
    AddressSet b(f.addr(0x200), f.addr(0x400));
    Address common = a.findFirstAddressInCommon(b);
    TEST("aset.firstCom.eq", common == f.addr(0x200));
}

void test_address_set_intersects_set() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x200));
    AddressSet b(f.addr(0x300), f.addr(0x400));
    AddressSet c(f.addr(0x150), f.addr(0x180));
    TEST("aset.ints.no",     !a.intersects(b));
    TEST("aset.ints.yes",     a.intersects(c));
    TEST("aset.ints.range",   a.intersects(f.addr(0x150), f.addr(0x250)));
}

void test_address_set_contains_set() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x300));
    AddressSet b(f.addr(0x150), f.addr(0x200));
    AddressSet c(f.addr(0x150), f.addr(0x400));
    TEST("aset.cntSet.sub",   a.contains(b));
    TEST("aset.cntSet.notsub",!a.contains(c));
}

void test_address_set_intersect_range() {
    YFixture f;
    AddressSet a(f.addr(0x100), f.addr(0x300));
    AddressSet r = a.intersectRange(f.addr(0x200), f.addr(0x400));
    TEST("aset.isecRng.lo", r.contains(f.addr(0x250)));
    TEST("aset.isecRng.notA",r.contains(f.addr(0x150)) == false);
    TEST("aset.isecRng.notB",r.contains(f.addr(0x350)) == false);
}

void test_address_set_address_count_before() {
    YFixture f;
    AddressSet s;
    s.add(f.addr(0x100), f.addr(0x103));
    TEST("aset.cntBefore.lo",  s.getAddressCountBefore(f.addr(0x100)) == 0);
    TEST("aset.cntBefore.mid",  s.getAddressCountBefore(f.addr(0x101)) == 1);
    TEST("aset.cntBefore.post", s.getAddressCountBefore(f.addr(0x200)) == 4);
}

void test_address_set_delete_range() {
    YFixture f;
    AddressSet s(f.addr(0x100), f.addr(0x300));
    s.deleteRange(f.addr(0x150), f.addr(0x250));
    TEST("aset.delRng.pre", s.contains(f.addr(0x130)));
    TEST("aset.delRng.mid", s.contains(f.addr(0x200)) == false);
    TEST("aset.delRng.post",s.contains(f.addr(0x290)));
}

void test_address_set_remove_range() {
    YFixture f;
    AddressSet s(f.addr(0x100), f.addr(0x300));
    s.remove(f.addr(0x150), f.addr(0x250));
    TEST("aset.remRng.pre",  s.contains(f.addr(0x130)));
    TEST("aset.remRng.mid",  s.contains(f.addr(0x200)) == false);
    TEST("aset.remRng.post", s.contains(f.addr(0x290)));
}

void test_address_set_remove_set() {
    YFixture f;
    AddressSet s(f.addr(0x100), f.addr(0x300));
    AddressSet sub(f.addr(0x150), f.addr(0x250));
    s.remove(sub);
    TEST("aset.remSet.pre", s.contains(f.addr(0x130)));
    TEST("aset.remSet.mid", s.contains(f.addr(0x200)) == false);
}

void test_address_set_add_range_ctor() {
    YFixture f;
    AddressSet s(AddressRange(f.addr(0x100), f.addr(0x200)));
    TEST("aset.addRng.contains", s.contains(f.addr(0x150)));
    TEST("aset.addRng.size",    s.getNumAddresses() == 0x101);
}

void test_address_set_add_range() {
    YFixture f;
    AddressSet s;
    s.addRange(f.addr(0x100), f.addr(0x103));
    TEST("aset.addRangeF.contains", s.contains(f.addr(0x102)));
    TEST("aset.addRangeF.count",    s.getNumAddresses() == 4);
}

void test_address_set_add_address() {
    YFixture f;
    AddressSet s;
    s.add(f.addr(0x100));
    TEST("aset.add1.contains", s.contains(f.addr(0x100)));
    TEST("aset.add1.count",    s.getNumAddresses() == 1);
}

void test_address_set_add_address_range() {
    YFixture f;
    AddressSet s;
    s.add(AddressRange(f.addr(0x100), f.addr(0x200)));
    TEST("aset.addRng2.contains", s.contains(f.addr(0x150)));
}

// ============ AddressIterator direct ============

void test_address_iterator_default() {
    AddressIterator it;
    TEST("ai.dflt.noNext", !it.hasNext());
    TEST("ai.dflt.remaining", it.remaining() == 0);
}

void test_address_iterator_with_vec() {
    YFixture f;
    std::vector<Address> v{f.addr(0x100), f.addr(0x200), f.addr(0x300)};
    AddressIterator it(v);
    TEST("ai.vec.hasNext", it.hasNext());
    TEST("ai.vec.remaining", it.remaining() == 3);
    Address a1 = it.next();
    TEST("ai.vec.first",  a1 == f.addr(0x100));
    Address a2 = it.next();
    TEST("ai.vec.second", a2 == f.addr(0x200));
    Address a3 = it.next();
    TEST("ai.vec.third",  a3 == f.addr(0x300));
    TEST("ai.vec.empty",  !it.hasNext());
    TEST("ai.vec.rem0",   it.remaining() == 0);
}

void test_address_iterator_reset() {
    YFixture f;
    std::vector<Address> v{f.addr(0x100), f.addr(0x200)};
    AddressIterator it(v);
    it.next();
    it.next();
    it.reset();
    TEST("ai.rst.hasNext", it.hasNext());
    Address a = it.next();
    TEST("ai.rst.first",   a == f.addr(0x100));
}

void test_address_iterator_current() {
    YFixture f;
    std::vector<Address> v{f.addr(0x100), f.addr(0x200)};
    AddressIterator it(v);
    TEST("ai.cur.initNull", it.current() == Address());
    Address a = it.next();
    TEST("ai.cur.afterNext", it.current() == a);
}

void test_address_iterator_empty_vec() {
    std::vector<Address> v;
    AddressIterator it(v);
    TEST("ai.empty.noNext", !it.hasNext());
    TEST("ai.empty.remaining", it.remaining() == 0);
}

// ============ AddressSetRangeIterator ============

void test_address_set_range_iter() {
    YFixture f;
    std::vector<AddressRange> ranges{
        AddressRange(f.addr(0x100), f.addr(0x200)),
        AddressRange(f.addr(0x300), f.addr(0x400)),
    };
    AddressSetRangeIterator it(ranges, f.addr(0x000), true);
    TEST("asri.fwd.hasNext", it.hasNext());
    AddressRange r1 = it.next();
    TEST("asri.fwd.r1.min", r1.getMinAddress() == f.addr(0x100));
    AddressRange r2 = it.next();
    TEST("asri.fwd.r2.min", r2.getMinAddress() == f.addr(0x300));
    TEST("asri.fwd.empty",  !it.hasNext());
}

// ============ AddressSetView via AddressSet (interface coverage) ============

void test_address_set_view_iface() {
    YFixture f;
    AddressSet s(f.addr(0x100), f.addr(0x200));
    AddressSetView* v = &s;
    TEST("asv.iface.contains", v->contains(f.addr(0x150)));
    TEST("asv.iface.containsR",v->contains(f.addr(0x100), f.addr(0x200)));
    TEST("asv.iface.notEmpty", !v->isEmpty());
}

// ============ ManagerDB NO_MANAGER constant ============

void test_manager_db_no_manager() {
    TEST("mdb.NO_MANAGER", ManagerDB::NO_MANAGER == -1);
}

int main() {
    std::cout << "\n--- AddressSetPropertyMap interface + impl ---\n";
    test_asp_interface_contract();
    test_asp_basic_add_remove();
    test_asp_add_set();
    test_asp_remove_set();
    test_asp_get_address_set();
    test_asp_get_addresses();
    test_asp_get_address_ranges();
    test_asp_clear();

    std::cout << "\n--- IntRangeMap interface + impl ---\n";
    test_irm_basic();
    test_irm_set_get();
    test_irm_multi_range();
    test_irm_clear_value();
    test_irm_overwrite();
    test_irm_negative_values();

    std::cout << "\n--- PropertyMapManager + ManagerDB ---\n";
    test_pmm_default_ctor();
    test_pmm_create_and_get_addrset();
    test_pmm_create_and_get_intrange();
    test_pmm_multi_create();
    test_pmm_delete_addrset();
    test_pmm_delete_intrange();
    test_pmm_delete_missing();
    test_pmm_recreate_same_name();
    test_pmm_set_program();
    test_pmm_program_ready();
    test_pmm_revision();
    test_pmm_clear_cache_all();
    test_pmm_clear_cache_partial();
    test_pmm_invalidate_cache();
    test_pmm_delete_address_range();
    test_pmm_move_address_range();

    std::cout << "\n--- AddressSet ---\n";
    test_address_set_basic();
    test_address_set_from_ctor();
    test_address_set_min_max();
    test_address_set_clear();
    test_address_set_union();
    test_address_set_intersect();
    test_address_set_subtract();
    test_address_set_xor();
    test_address_set_equality();
    test_address_set_hasSameAddresses();
    test_address_set_count();
    test_address_set_print();
    test_address_set_toList();
    test_address_set_getRangeContaining();
    test_address_set_first_last_range();
    test_address_set_findFirstCommon();
    test_address_set_intersects_set();
    test_address_set_contains_set();
    test_address_set_intersect_range();
    test_address_set_address_count_before();
    test_address_set_delete_range();
    test_address_set_remove_range();
    test_address_set_remove_set();
    test_address_set_add_range_ctor();
    test_address_set_add_range();
    test_address_set_add_address();
    test_address_set_add_address_range();

    std::cout << "\n--- AddressIterator + AddressSetRangeIterator ---\n";
    test_address_iterator_default();
    test_address_iterator_with_vec();
    test_address_iterator_reset();
    test_address_iterator_current();
    test_address_iterator_empty_vec();
    test_address_set_range_iter();

    std::cout << "\n--- AddressSetView + ManagerDB constant ---\n";
    test_address_set_view_iface();
    test_manager_db_no_manager();

    std::cout << "\n=== Batch Y: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
