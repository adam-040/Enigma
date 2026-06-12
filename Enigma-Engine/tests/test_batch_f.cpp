/**
 * Enigma Engine - Batch F (model.pcode Packed encoder/decoder) Test
 * Smoke tests for PackedBytes, PackedEncode, PackedDecode, PatchEncoder,
 * PatchPackedEncode.
 */
#include <ghidra/PackedBytes.h>
#include <ghidra/PackedEncode.h>
#include <ghidra/PackedDecode.h>
#include <ghidra/PatchEncoder.h>
#include <ghidra/PatchPackedEncode.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <iostream>
#include <stdexcept>
#include <cstring>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

int main() {
    std::cout << "=== Batch F (model.pcode Packed encoder/decoder) Test ===\n";

    {
        PackedBytes pb(64);
        TEST("PackedBytes initial size 0", pb.size() == 0);
        pb.writeByte(0x42);
        pb.writeByte(0x99);
        TEST("PackedBytes size after 2 writes", pb.size() == 2);
        TEST("PackedBytes getByte", pb.getByte(0) == 0x42);
        TEST("PackedBytes getByte 2", pb.getByte(1) == 0x99);
        pb.insertByte(0, 0x11);
        TEST("PackedBytes insertByte", pb.getByte(0) == 0x11);
        TEST("PackedBytes still size 2", pb.size() == 2);

        int idx = pb.find(0, 0x99);
        TEST("PackedBytes find 0x99 at 1", idx == 1);
        idx = pb.find(0, 0xFF);
        TEST("PackedBytes find missing -1", idx == -1);

        uint8_t src[] = {0xAB, 0xCD, 0xEF};
        pb.writeBytes(src, 0, 3);
        TEST("PackedBytes size after block write", pb.size() == 5);
        TEST("PackedBytes block write 0", pb.getByte(2) == 0xAB);

        std::vector<uint8_t> out;
        pb.writeTo(out);
        TEST("PackedBytes writeTo size", out.size() == 5);
        TEST("PackedBytes writeTo 0", out[0] == 0x11);
    }

    {
        PackedEncode enc;
        ElementId elemBlock = ELEM_BLOCK;
        AttributeId attrName = ATTRIB_NAME;
        enc.openElement(elemBlock);
        enc.writeString(attrName, "hello");
        enc.writeSignedInteger(attrName, -42);
        enc.writeUnsignedInteger(attrName, 0x1234);
        enc.writeBool(attrName, true);
        enc.closeElement(elemBlock);

        TEST("PackedEncode non-empty", enc.size() > 0);

        std::vector<uint8_t> bytes;
        enc.getBytes(bytes);
        TEST("PackedEncode getBytes non-empty", !bytes.empty());
        TEST("PackedEncode first byte is ELEMENT_START", (bytes[0] & 0xc0) == 0x40);

        PackedDecode dec;
        dec.ingest(bytes.data(), (int)bytes.size());
        int id = dec.openElement();
        TEST("PackedDecode openElement returns ELEM_BLOCK id", id == ELEM_BLOCK.id);

        int attrId = dec.getNextAttributeId();
        TEST("PackedDecode getNextAttributeId name", attrId == ATTRIB_NAME.id);
        std::string s = dec.readString();
        TEST("PackedDecode readString == hello", s == "hello");

        attrId = dec.getNextAttributeId();
        TEST("PackedDecode getNextAttributeId name again", attrId == ATTRIB_NAME.id);
        int sv = dec.readSignedInteger();
        TEST("PackedDecode readSignedInteger -42", sv == -42);

        attrId = dec.getNextAttributeId();
        TEST("PackedDecode getNextAttributeId name again2", attrId == ATTRIB_NAME.id);
        uint64_t uv = dec.readUnsignedInteger();
        TEST("PackedDecode readUnsignedInteger 0x1234", uv == 0x1234);

        attrId = dec.getNextAttributeId();
        TEST("PackedDecode getNextAttributeId name again3", attrId == ATTRIB_NAME.id);
        bool bv = dec.readBool();
        TEST("PackedDecode readBool true", bv);

        attrId = dec.getNextAttributeId();
        TEST("PackedDecode no more attrs", attrId == 0);

        dec.closeElement(id);
    }

    {
        PackedEncode enc;
        ElementId elemX = ELEM_BHEAD;
        AttributeId attrVal = ATTRIB_VAL;
        enc.openElement(elemX);
        enc.writeSignedInteger(attrVal, 1234567890LL);
        enc.closeElement(elemX);

        std::vector<uint8_t> bytes;
        enc.getBytes(bytes);

        PackedDecode dec;
        dec.ingest(bytes.data(), (int)bytes.size());
        int id = dec.openElement();
        TEST("Big int element id BHEAD", id == ELEM_BHEAD.id);
        int aid = dec.getNextAttributeId();
        TEST("Big int attr id VAL", aid == ATTRIB_VAL.id);
        int64_t v = dec.readSignedInteger();
        TEST("Big int value", v == 1234567890LL);
        dec.closeElement(id);
    }

    {
        PackedEncode enc;
        AttributeId attrName = ATTRIB_NAME;
        enc.writeString(attrName, "test");
        std::vector<uint8_t> bytes;
        enc.getBytes(bytes);
        PackedDecode dec;
        dec.ingest(bytes.data(), (int)bytes.size());
        int aid = dec.getNextAttributeId();
        TEST("Direct attr id", aid == ATTRIB_NAME.id);
        std::string s = dec.readString();
        TEST("Direct readString", s == "test");
    }

    {
        PatchPackedEncode penc;
        AttributeId attrId = ATTRIB_ID;
        ElementId elem1 = ELEM_EDGE;
        int pos = penc.size();
        penc.openElement(elem1);
        penc.writeSignedInteger(attrId, 0);
        penc.closeElement(elem1);
        TEST("PatchPackedEncode initial size > 0", penc.size() > 0);
        TEST("PatchPackedEncode isEmpty false", !penc.isEmpty());

        bool patched = penc.patchIntegerAttribute(pos, attrId, 999);
        TEST("PatchPackedEncode patchIntegerAttribute", patched);
    }

    {
        PatchPackedEncode penc;
        AttributeId attrId = ATTRIB_ID;
        ElementId elem1 = ELEM_EDGE;
        int pos = penc.size();
        penc.openElement(elem1);
        penc.writeSignedInteger(attrId, 0);
        penc.closeElement(elem1);

        bool patched = penc.patchIntegerAttribute(pos, attrId, 0x123456789ABCDEFLL);
        TEST("PatchPackedEncode patch large int", patched);

        std::stringstream ss;
        penc.writeTo(ss);
        std::string after = ss.str();
        TEST("PatchPackedEncode writeTo non-empty", !after.empty());
    }

    {
        PackedEncode enc;
        AttributeId attrName = ATTRIB_NAME;
        enc.writeString(attrName, "first");
        enc.writeString(attrName, "second");
        std::vector<uint8_t> bytes;
        enc.getBytes(bytes);
        PackedDecode dec;
        dec.ingest(bytes.data(), (int)bytes.size());

        int a1 = dec.getNextAttributeId();
        TEST("Indexed attr 1", a1 == ATTRIB_NAME.id);
        std::string s1 = dec.readString();
        TEST("Indexed string first", s1 == "first");

        int a2 = dec.getNextAttributeId();
        TEST("Indexed attr 2", a2 == ATTRIB_NAME.id);
        std::string s2 = dec.readString();
        TEST("Indexed string second", s2 == "second");
    }

    {
        PackedEncode enc;
        PackedEncode* penc = &enc;
        AttributeId attrName = ATTRIB_NAME;
        enc.writeBool(attrName, false);
        enc.writeBool(attrName, true);
        std::vector<uint8_t> bytes;
        enc.getBytes(bytes);
        PackedDecode dec;
        dec.ingest(bytes.data(), (int)bytes.size());
        int a1 = dec.getNextAttributeId();
        TEST("Bool false attr", a1 == ATTRIB_NAME.id);
        bool b1 = dec.readBool();
        TEST("Bool false value", !b1);
        int a2 = dec.getNextAttributeId();
        TEST("Bool true attr", a2 == ATTRIB_NAME.id);
        bool b2 = dec.readBool();
        TEST("Bool true value", b2);
    }

    {
        PackedEncode enc;
        AttributeId attrName = ATTRIB_NAME;
        enc.clear();
        enc.writeString(attrName, "afterClear");
        std::vector<uint8_t> bytes;
        enc.getBytes(bytes);
        PackedDecode dec;
        dec.ingest(bytes.data(), (int)bytes.size());
        int a = dec.getNextAttributeId();
        TEST("After clear attr", a == ATTRIB_NAME.id);
        std::string s = dec.readString();
        TEST("After clear string", s == "afterClear");
    }

    std::cout << "=== Batch F: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
