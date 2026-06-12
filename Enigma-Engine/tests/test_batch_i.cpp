/**
 * Enigma Engine - Batch I (SegmentedAddressSpace / ProtectedAddressSpace / SegmentedAddress) Test
 * Smoke tests for the x86 real-mode + protected-mode segmented address classes.
 */
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/SegmentedAddress.h>
#include <ghidra/SegmentedAddressSpace.h>
#include <ghidra/ProtectedAddressSpace.h>
#include <ghidra/AddressFormatException.h>
#include <iostream>
#include <stdexcept>
#include <cstring>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

int main() {
    std::cout << "=== Batch I (SegmentedAddressSpace / ProtectedAddressSpace / SegmentedAddress) Test ===\n";

    // ---------- SegmentedAddressSpace (real-mode) ----------
    {
        SegmentedAddressSpace realmode("realm", 100);
        TEST("real size 21",       realmode.getSize() == 21);
        TEST("real type RAM",      realmode.getType() == AddressSpace::TYPE_RAM);
        TEST("real name",          realmode.getName() == "realm");
        TEST("real unique 100",    realmode.getUnique() == 100);
        TEST("real pointer 2",     realmode.getPointerSize() == 2);
        TEST("real max REALMODE",  realmode.getMaxOffset() == SegmentedAddressSpace::REALMODE_MAXOFFSET);
        TEST("real RAM space",     realmode.isMemorySpace());
        TEST("real loaded",        realmode.isLoadedMemorySpace());
        TEST("real not overlay",   !realmode.isOverlaySpace());

        // getFlatOffset: seg << 4 | offset
        TEST("real flat(0x100,0x010) = 0x1010",
             realmode.getFlatOffset(0x100, 0x010) == 0x1010);
        TEST("real flat(0xFFF,0x000F) = 0xFFFF",
             realmode.getFlatOffset(0xFFF, 0x000F) == 0xFFFF);
        TEST("real flat(0,0) = 0",
             realmode.getFlatOffset(0, 0) == 0);

        // getDefaultSegmentFromFlat
        TEST("real seg 0x1000 from flat 0x10000",
             realmode.getDefaultSegmentFromFlat(0x10000) == 0x1000);
        TEST("real seg 0xFFFF from flat > 0xFFFFF",
             realmode.getDefaultSegmentFromFlat(0x100000) == 0xFFFF);

        // getDefaultOffsetFromFlat
        TEST("real off 0x0042 from flat 0x10042",
             realmode.getDefaultOffsetFromFlat(0x10042) == 0x0042);
        TEST("real off 0xFFFF from flat 0x10FFEF",
             realmode.getDefaultOffsetFromFlat(0x10FFEF) == 0xFFFF);

        // getOffsetFromFlat (uses preferred segment)
        TEST("real offsetFromFlat(0x12345, 0x1230) = 0x45",
             realmode.getOffsetFromFlat(0x12345, 0x1230) == 0x45);

        // getAddress(seg, off) -> SegmentedAddress (returned by value)
        SegmentedAddress a = realmode.getAddress(0x1000, 0x0042);
        TEST("real Address(0x1000,0x0042) flat 0x10042",
             a.getOffset() == 0x10042);
        TEST("real Address in SegmentedAddressSpace",
             a.getAddressSpace() == static_cast<AddressSpace*>(&realmode));
        TEST("real seg 0x1000", a.getSegment() == 0x1000);
        TEST("real segOff 0x0042", a.getSegmentOffset() == 0x0042);

        // getAddress(flat) returns a plain Address
        Address flatAddr = realmode.getAddress(0x10042);
        TEST("real getAddress(flat) offset 0x10042",
             flatAddr.getOffset() == 0x10042);
        TEST("real getSegmentFromAddress",
             realmode.getSegmentFromAddress(flatAddr) == 0x1000);

        // getNextOpenSegment
        Address na(0, 0x12340);
        TEST("real nextOpenSegment 0x1235",
             realmode.getNextOpenSegment(na) == 0x1235);

        // getAddress(string)
        Address parsed = realmode.getAddress(std::string("0x10042"), true);
        TEST("real parse hex 0x10042", parsed.getOffset() == 0x10042);
        Address parsedSeg = realmode.getAddress(std::string("1000:0042"), true);
        TEST("real parse seg 1000:0042", parsedSeg.getOffset() == 0x10042);
    }

    // ---------- ProtectedAddressSpace ----------
    {
        ProtectedAddressSpace protmode("protm", 200);
        TEST("prot size 32",        protmode.getSize() == 32);
        TEST("prot name",           protmode.getName() == "protm");
        TEST("prot unique 200",     protmode.getUnique() == 200);
        TEST("prot pointer 2",      protmode.getPointerSize() == 2);
        TEST("prot max",            protmode.getMaxOffset() > 0);
        TEST("prot RAM space",      protmode.isMemorySpace());

        // getFlatOffset: (seg << 16) | offset
        TEST("prot flat(0x1000, 0x0042) = 0x10000042",
             protmode.getFlatOffset(0x1000, 0x0042) == 0x10000042ULL);
        TEST("prot flat(0x0000, 0x0000) = 0",
             protmode.getFlatOffset(0, 0) == 0);
        TEST("prot flat(0xFFFF, 0xFFFF) = 0xFFFFFFFF",
             protmode.getFlatOffset(0xFFFF, 0xFFFF) == 0xFFFFFFFFLL);

        // getDefaultSegmentFromFlat
        TEST("prot seg from 0x10000042 = 0x1000",
             protmode.getDefaultSegmentFromFlat(0x10000042LL) == 0x1000);
        TEST("prot seg from 0 = 0",
             protmode.getDefaultSegmentFromFlat(0) == 0);
        TEST("prot seg from 0xFFFFFFFF = 0xFFFF",
             protmode.getDefaultSegmentFromFlat(0xFFFFFFFFLL) == 0xFFFF);

        // getDefaultOffsetFromFlat
        TEST("prot off from 0x10000042 = 0x42",
             protmode.getDefaultOffsetFromFlat(0x10000042LL) == 0x42);
        TEST("prot off from 0xFFFFFFFF = 0xFFFF",
             protmode.getDefaultOffsetFromFlat(0xFFFFFFFFLL) == 0xFFFF);

        // getOffsetFromFlat ignores segment
        TEST("prot offFromFlat(0x10000042, 0) = 0x42",
             protmode.getOffsetFromFlat(0x10000042LL, 0) == 0x42);

        // getAddressInSegment returns nullopt (unique encoding)
        Address dummy(0, 0x10000042LL);
        TEST("prot getAddressInSegment nullopt",
             !protmode.getAddressInSegment(0x10000042LL, 0x1000).has_value());

        // getAddress(seg, off)
        SegmentedAddress pa = protmode.getAddress(0x1000, 0x0042);
        TEST("prot getAddress(0x1000,0x0042) flat 0x10000042",
             pa.getOffset() == 0x10000042LL);
        TEST("prot seg 0x1000", pa.getSegment() == 0x1000);
        TEST("prot segOff 0x0042", pa.getSegmentOffset() == 0x0042);

        // getNextOpenSegment: skips by 8, masking to 0xfff8
        Address na(0, 0x10000042LL);
        TEST("prot nextOpenSegment mask",
             (protmode.getNextOpenSegment(na) & 0xfff8) == protmode.getNextOpenSegment(na));
    }

    // ---------- SegmentedAddress value semantics ----------
    {
        SegmentedAddressSpace realmode("realm", 100);
        SegmentedAddress a1(0x10042, &realmode);
        TEST("seg addr1 segment",     a1.getSegment() == 0x1000);
        TEST("seg addr1 segOffset",   a1.getSegmentOffset() == 0x0042);
        TEST("seg addr1 flat",        a1.getOffset() == 0x10042);
        TEST("seg addr1 toString",    a1.toString() == "1000:0042");

        SegmentedAddress a2(&realmode, 0x2000, 0x0080);
        TEST("seg addr2 segment",     a2.getSegment() == 0x2000);
        TEST("seg addr2 segOffset",   a2.getSegmentOffset() == 0x0080);
        TEST("seg addr2 flat 0x20080", a2.getOffset() == 0x20080);

        SegmentedAddress a3(0x10042, &realmode);
        SegmentedAddress a4(0x10042, &realmode);
        TEST("seg addr equality", a3 == a4);
        TEST("seg addr inequality", a1 != a2);

        SegmentedAddress def;
        TEST("seg default invalid", !def.isValid());
    }

    // ---------- GenericAddressSpace getAddress still works ----------
    {
        GenericAddressSpace gas("ram", 32, AddressSpace::TYPE_RAM, 0);
        Address a = gas.getAddress(0x1000);
        TEST("gas getAddress(0x1000) flat", a.getOffset() == 0x1000);
        Address parsed = gas.getAddress(std::string("0x2000"), true);
        TEST("gas getAddress(\"0x2000\") flat", parsed.getOffset() == 0x2000);
        Address parsed2 = gas.getAddress(std::string("8192"), true);
        TEST("gas getAddress(\"8192\") flat", parsed2.getOffset() == 8192);
    }

    std::cout << "=== Batch I: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
