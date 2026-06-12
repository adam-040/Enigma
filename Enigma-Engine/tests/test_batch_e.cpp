/**
 * Enigma Engine - Batch E (model.util + model.address) Test
 * Smoke tests for classes ported in W138:
 *   AddressCollectors, AddressRangeToAddressComparator, ProcessorSymbolType,
 *   DataTypeInfo, CompositeDataTypeElementInfo, PropertySet,
 *   DefaultIntPropertyMap, MemoryByteIterator.
 */
#include <ghidra/AddressCollectors.h>
#include <ghidra/AddressRangeToAddressComparator.h>
#include <ghidra/ProcessorSymbolType.h>
#include <ghidra/DataTypeInfo.h>
#include <ghidra/PropertySet.h>
#include <ghidra/DefaultIntPropertyMap.h>
#include <ghidra/MemoryByteIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Memory.h>
#include <iostream>
#include <stdexcept>
#include <cstring>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

int main() {
    std::cout << "=== Batch E (model.util + model.address) Test ===\n";

    GenericAddressSpace sp("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address a1(&sp, 0x100);
    Address a2(&sp, 0x200);
    Address a3(&sp, 0x300);
    Address a4(&sp, 0x400);

    {
        AddressRange r1(a1, a2);
        AddressRange r2(a3, a4);
        std::vector<AddressRange> ranges = {r1, r2};
        AddressSet s = AddressCollectors::toAddressSet(ranges);
        TEST("AddressCollectors size", s.getNumAddresses() == (0x200 - 0x100 + 1) + (0x400 - 0x300 + 1));
        TEST("AddressCollectors has a1", s.contains(a1));
        TEST("AddressCollectors has a3", s.contains(a3));
        TEST("AddressCollectors not has a2+1", !s.contains(Address(&sp, 0x250)));
    }

    {
        AddressRangeToAddressComparator cmp;
        AddressRange r(a1, a2);
        Address inside(&sp, 0x150);
        Address before(&sp, 0x050);
        Address after(&sp, 0x350);
        Address* pInside = &inside;
        Address* pBefore = &before;
        Address* pAfter = &after;
        AddressRange* pR = &r;
        TEST("cmp range inside == 0", cmp.compareRangeToAddress(pR, pInside) == 0);
        TEST("cmp range>addr before", cmp.compareRangeToAddress(pR, pBefore) > 0);
        TEST("cmp range<addr after", cmp.compareRangeToAddress(pR, pAfter) < 0);
    }

    {
        TEST("ProcessorSymbolTypes code", ProcessorSymbolTypes::getType("code") == ProcessorSymbolType::CODE);
        TEST("ProcessorSymbolTypes CODE_PTR", ProcessorSymbolTypes::getType("code_ptr") == ProcessorSymbolType::CODE_PTR);
        TEST("ProcessorSymbolTypes uppercase", ProcessorSymbolTypes::getType("CODE") == ProcessorSymbolType::CODE);
        bool threw = false;
        try { ProcessorSymbolTypes::getType("invalid"); } catch (...) { threw = true; }
        TEST("ProcessorSymbolTypes invalid throws", threw);
        TEST("ProcessorSymbolTypes toString CODE", std::strcmp(ProcessorSymbolTypes::toString(ProcessorSymbolType::CODE), "code") == 0);
        TEST("ProcessorSymbolTypes toString CODE_PTR", std::strcmp(ProcessorSymbolTypes::toString(ProcessorSymbolType::CODE_PTR), "code_ptr") == 0);
    }

    {
        int handleA = 42;
        int handleB = 99;
        DataTypeInfo di1(&handleA, 4, 4);
        DataTypeInfo di2(&handleA, 4, 4);
        DataTypeInfo di3(&handleB, 4, 4);
        TEST("DataTypeInfo length", di1.getDataTypeLength() == 4);
        TEST("DataTypeInfo alignment", di1.getDataTypeAlignment() == 4);
        TEST("DataTypeInfo handle", di1.getDataTypeHandle() == &handleA);
        TEST("DataTypeInfo equals", di1.equals(di2));
        TEST("DataTypeInfo !equals handle", !di1.equals(di3));
        TEST("DataTypeInfo hashCode eq", di1.hashCode() == di2.hashCode());
    }

    {
        int h = 7;
        CompositeDataTypeElementInfo cdei(&h, 8, 4, 4);
        TEST("Composite offset", cdei.getDataTypeOffset() == 8);
        TEST("Composite inherits length", cdei.getDataTypeLength() == 4);
        TEST("Composite inherits alignment", cdei.getDataTypeAlignment() == 4);
        CompositeDataTypeElementInfo cdei2(&h, 8, 4, 4);
        TEST("Composite equals", cdei.equals(cdei2));
        std::string s = cdei.toString();
        TEST("Composite toString not empty", !s.empty());
    }

    {
        DefaultIntPropertyMap pm("test");
        TEST("DefaultIntPropertyMap name", pm.getName() == "test");
        TEST("DefaultIntPropertyMap initial size", pm.getSize() == 0);
        TEST("DefaultIntPropertyMap getValueClass", pm.getValueClass() == typeid(int32_t));
        TEST("DefaultIntPropertyMap !hasProperty", !pm.hasProperty(a1));

        pm.add(a1, 42);
        pm.add(a2, 100);
        TEST("DefaultIntPropertyMap size after add", pm.getSize() == 2);
        TEST("DefaultIntPropertyMap hasProperty a1", pm.hasProperty(a1));
        TEST("DefaultIntPropertyMap getInt a1", pm.getInt(a1) == 42);
        TEST("DefaultIntPropertyMap getInt a2", pm.getInt(a2) == 100);

        bool threw = false;
        try { pm.getInt(a3); } catch (NoValueException&) { threw = true; }
        TEST("DefaultIntPropertyMap getInt missing throws", threw);

        Address firstAddr = pm.getFirstPropertyAddress();
        TEST("DefaultIntPropertyMap firstAddr", firstAddr.getOffset() == 0x100);
        Address lastAddr = pm.getLastPropertyAddress();
        TEST("DefaultIntPropertyMap lastAddr", lastAddr.getOffset() == 0x200);

        Address nextOf1 = pm.getNextPropertyAddress(a1);
        TEST("DefaultIntPropertyMap nextOf1", nextOf1.getOffset() == 0x200);

        TEST("DefaultIntPropertyMap intersects", pm.intersects(a1, a2));
        TEST("DefaultIntPropertyMap !intersects far", !pm.intersects(Address(&sp, 0x500), Address(&sp, 0x600)));

        AddressIterator* rangeIt = pm.getPropertyIterator(a1, a2);
        TEST("DefaultIntPropertyMap range iterator has first", rangeIt->hasNext());
        TEST("DefaultIntPropertyMap range iterator first", rangeIt->next().getOffset() == 0x100);
        TEST("DefaultIntPropertyMap range iterator second", rangeIt->next().getOffset() == 0x200);
        TEST("DefaultIntPropertyMap range iterator done", !rangeIt->hasNext());
        delete rangeIt;

        AddressIterator* reverseIt = pm.getPropertyIterator(a1, a2, false);
        TEST("DefaultIntPropertyMap reverse iterator first", reverseIt->next().getOffset() == 0x200);
        TEST("DefaultIntPropertyMap reverse iterator second", reverseIt->next().getOffset() == 0x100);
        delete reverseIt;

        AddressSet pmSet;
        pmSet.add(a2, a2);
        AddressIterator* setIt = pm.getPropertyIterator(pmSet);
        TEST("DefaultIntPropertyMap set iterator one", setIt->hasNext() && setIt->next().getOffset() == 0x200);
        TEST("DefaultIntPropertyMap set iterator done", !setIt->hasNext());
        delete setIt;

        pm.moveRange(a1, a2, Address(&sp, 0x400));
        TEST("DefaultIntPropertyMap moveRange old gone", !pm.hasProperty(a1) && !pm.hasProperty(a2));
        TEST("DefaultIntPropertyMap moveRange first value", pm.getInt(Address(&sp, 0x400)) == 42);
        TEST("DefaultIntPropertyMap moveRange second value", pm.getInt(Address(&sp, 0x500)) == 100);

        TEST("DefaultIntPropertyMap remove moved first", pm.remove(Address(&sp, 0x400)));
        TEST("DefaultIntPropertyMap !hasProperty moved first after rm", !pm.hasProperty(Address(&sp, 0x400)));
        TEST("DefaultIntPropertyMap size after rm", pm.getSize() == 1);

        pm.clear();
        TEST("DefaultIntPropertyMap size after clear", pm.getSize() == 0);

        pm.setDescription("Test map");
        TEST("DefaultIntPropertyMap description", pm.getDescription() == "Test map");
    }

    {
        DefaultMemory mem(true);
        DefaultMemoryBlock* blk = mem.createInitializedBlock("test", a1, 0x400);
        uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD};
        blk->putBytes(a1, data, 4);
        blk->putBytes(Address(&sp, 0x300), data, 4);

        AddressSet set;
        set.add(a1, Address(&sp, 0x103));
        set.add(Address(&sp, 0x300), Address(&sp, 0x303));

        MemoryByteIterator it(&mem, set);
        TEST("MemoryByteIterator hasNext initial", it.hasNext());
        int count = 0;
        while (it.hasNext()) {
            it.nextByte();
            count++;
        }
        TEST("MemoryByteIterator count 8 bytes", count == 8);
    }

    {
        DefaultMemory mem(true);
        AddressSet set;
        MemoryByteIterator it(&mem, set);
        TEST("MemoryByteIterator empty set no next", !it.hasNext());
    }

    std::cout << "=== Batch E: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
