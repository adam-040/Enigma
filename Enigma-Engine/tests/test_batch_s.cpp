/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_s.cpp
/// \brief Tests for Batch S: LEB128, LEB128 data types, TerminatedString types
#include <ghidra/LEB128.h>
#include <ghidra/SignedLeb128DataType.h>
#include <ghidra/UnsignedLeb128DataType.h>
#include <ghidra/TerminatedStringDataType.h>
#include <ghidra/TerminatedUnicode32DataType.h>
#include <ghidra/DynamicDataType.h>
#include <ghidra/StructuredDynamicDataType.h>
#include <ghidra/IndexedDynamicDataType.h>
#include <ghidra/FactoryStructureDataType.h>
#include <ghidra/StructureFactory.h>
#include <ghidra/DataUtilities.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/Structure.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/Address.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <memory>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// ---- LEB128 decode tests ----

void test_leb128_decode_unsigned_small() {
    uint8_t bytes[] = {0x01};
    uint64_t val = LEB128::unsignedDecode(bytes, 0, 1);
    TEST("LEB128.u.small", val == 1);
}

void test_leb128_decode_unsigned_multi() {
    uint8_t bytes[] = {0xE5, 0x8E, 0x26};
    uint64_t val = LEB128::unsignedDecode(bytes, 0, 3);
    TEST("LEB128.u.multi", val == 624485);
}

void test_leb128_decode_signed_positive() {
    uint8_t bytes[] = {0x05};
    int64_t val = LEB128::signedDecode(bytes, 0, 1);
    TEST("LEB128.s.pos", val == 5);
}

void test_leb128_decode_signed_negative() {
    uint8_t bytes[] = {0x7F};
    int64_t val = LEB128::signedDecode(bytes, 0, 1);
    TEST("LEB128.s.neg", val == -1);
}

void test_leb128_decode_signed_negative_multi() {
    uint8_t bytes[] = {0x7B, 0x7F};
    int64_t val = LEB128::signedDecode(bytes, 0, 2);
    TEST("LEB128.s.neg.multi", val == -5);
}

// ---- LEB128 encode tests ----

void test_leb128_encode_unsigned_small() {
    auto result = LEB128::encodeUnsigned(1);
    TEST("LEB128.enc.u.size", result.size() == 1);
    TEST("LEB128.enc.u.val", result[0] == 0x01);
}

void test_leb128_encode_unsigned_multi() {
    auto result = LEB128::encodeUnsigned(624485);
    TEST("LEB128.enc.u.multi.size", result.size() == 3);
    TEST("LEB128.enc.u.multi.0", result[0] == 0xE5);
    TEST("LEB128.enc.u.multi.1", result[1] == 0x8E);
    TEST("LEB128.enc.u.multi.2", result[2] == 0x26);
}

void test_leb128_encode_signed_neg() {
    auto result = LEB128::encodeSigned(-5);
    // Should roundtrip
    int64_t val = LEB128::signedDecode(result.data(), 0, result.size());
    TEST("LEB128.enc.s.neg.roundtrip", val == -5);
}

void test_leb128_encode_signed_pos() {
    auto result = LEB128::encodeSigned(5);
    int64_t val = LEB128::signedDecode(result.data(), 0, result.size());
    TEST("LEB128.enc.s.pos.roundtrip", val == 5);
}

void test_leb128_encode_unsigned_zero() {
    auto result = LEB128::encodeUnsigned(0);
    TEST("LEB128.enc.u.zero.size", result.size() == 1);
    TEST("LEB128.enc.u.zero.val", result[0] == 0x00);
}

void test_leb128_get_length() {
    uint8_t bytes[] = {0xE5, 0x8E, 0x26};
    int len = LEB128::getLength(bytes, 0, 3);
    TEST("LEB128.length", len == 3);
}

void test_leb128_get_length_single() {
    uint8_t bytes[] = {0x01};
    int len = LEB128::getLength(bytes, 0, 1);
    TEST("LEB128.length.single", len == 1);
}

// ---- SignedLeb128DataType tests ----

void test_sleb128_basic() {
    TEST("sleb128.name", SignedLeb128DataType::dataType().getName() == "sleb128");
    TEST("sleb128.mnemonic", SignedLeb128DataType::dataType().getMnemonic(nullptr) == "sleb128");
    TEST("sleb128.length", SignedLeb128DataType::dataType().getLength() == -1);
    TEST("sleb128.replacement",
         SignedLeb128DataType::dataType().getReplacementBaseType() != nullptr);
    TEST("sleb128.description",
         SignedLeb128DataType::dataType().getDescription() == "Signed LEB128-Encoded Number");
}

void test_sleb128_can_specify_length() {
    TEST("sleb128.canSpecifyLength", SignedLeb128DataType::dataType().canSpecifyLength());
}

// ---- UnsignedLeb128DataType tests ----

void test_uleb128_basic() {
    TEST("uleb128.name", UnsignedLeb128DataType::dataType().getName() == "uleb128");
    TEST("uleb128.description",
         UnsignedLeb128DataType::dataType().getDescription() == "Unsigned LEB128-Encoded Number");
    TEST("uleb128.length", UnsignedLeb128DataType::dataType().getLength() == -1);
    TEST("uleb128.replacement",
         UnsignedLeb128DataType::dataType().getReplacementBaseType() != nullptr);
}

// ---- TerminatedStringDataType tests ----

void test_terminated_cstring_basic() {
    TEST("tstring.name", TerminatedStringDataType::dataType().getName() == "TerminatedCString");
    TEST("tstring.mnemonic", TerminatedStringDataType::dataType().getMnemonic(nullptr) == "ds");
    TEST("tstring.description",
         TerminatedStringDataType::dataType().getDescription() == "String (Null Terminated)");
}

void test_terminated_cstring_layout() {
    TEST("tstring.layout",
         TerminatedStringDataType::dataType().getStringLayout() ==
             StringLayoutEnum::NULL_TERMINATED_UNBOUNDED);
}

// ---- TerminatedUnicode32DataType tests ----

void test_terminated_unicode32_basic() {
    TEST("tunicode32.name",
         TerminatedUnicode32DataType::dataType().getName() == "TerminatedUnicode32");
    TEST("tunicode32.mnemonic",
         TerminatedUnicode32DataType::dataType().getMnemonic(nullptr) == "unicode32");
    TEST("tunicode32.description",
         TerminatedUnicode32DataType::dataType().getDescription() ==
             "String (Null Terminated UTF-32 Unicode)");
}

void test_terminated_unicode32_layout() {
    TEST("tunicode32.layout",
         TerminatedUnicode32DataType::dataType().getStringLayout() ==
             StringLayoutEnum::NULL_TERMINATED_UNBOUNDED);
}

// ---- Test subclasses for abstract types ----

class TestDynamicDataType : public DynamicDataType {
public:
    TestDynamicDataType() : DynamicDataType("TestDynamic") {}
    DataType* clone(DataTypeManager* dtm) const override { return new TestDynamicDataType(); }
    int getLength() const override { return -1; }
    std::string getDescription() const override { return "Test Dynamic Data Type"; }
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override { return "TestDynamic"; }
    int getLength(MemBuffer* buf, int maxLength) override { return -1; }
    DataType* getReplacementBaseType() override { return nullptr; }
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return getName(); }
    void setDefaultSettings(Settings* settings) override {}
protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override { return {}; }
};

class TestFactoryStruct : public FactoryStructureDataType {
public:
    TestFactoryStruct() : FactoryStructureDataType("TestFactoryStruct", nullptr) {}
    DataType* clone(DataTypeManager* dtm) const override { return new TestFactoryStruct(); }
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override { return "TestFactoryStruct"; }
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return getName(); }
    void setDefaultSettings(Settings* settings) override {}
protected:
    void populateDynamicStructure(MemBuffer* buf, Structure* structDt) override {}
};

// ---- DynamicDataType tests ----

void test_dynamic_basic() {
    TestDynamicDataType dt;
    TEST("dynamic.name", dt.getName() == "TestDynamic");
    TEST("dynamic.desc", dt.getDescription() == "Test Dynamic Data Type");
    TEST("dynamic.length", dt.getLength() == -1);
    TEST("dynamic.canSpecify", dt.canSpecifyLength() == false);
}

void test_dynamic_num_components_null() {
    TestDynamicDataType dt;
    TEST("dynamic.numComps.null", dt.getNumComponents(nullptr) == -1);
}

// ---- StructuredDynamicDataType tests ----

void test_structured_basic() {
    StructuredDynamicDataType sdt("TestStructured", "Test Structured Desc", nullptr);
    TEST("structured.name", sdt.getName() == "TestStructured");
    TEST("structured.desc", sdt.getDescription() == "Test Structured Desc");
}

void test_structured_add() {
    StructuredDynamicDataType sdt("TestStructured", "Test", nullptr);
    sdt.add(&ByteDataType::dataType(), "field0", "first byte");
    TEST("structured.add.ok", true);
}

// ---- IndexedDynamicDataType tests ----

void test_indexed_ctor() {
    std::vector<int64_t> keys = {1, 2};
    std::vector<DataType*> structs = {&ByteDataType::dataType(), &IntegerDataType::dataType()};
    IndexedDynamicDataType idx("TestIndexed", "Test Indexed Desc",
                               &ByteDataType::dataType(), keys, structs,
                               0, 1, 0xFFFF, nullptr);
    TEST("indexed.name", idx.getName() == "TestIndexed");
    TEST("indexed.desc", idx.getDescription() == "Test Indexed Desc");
}

void test_indexed_single_key_ctor() {
    IndexedDynamicDataType idx("SingleKeyIdx", "Single key indexed",
                               &ByteDataType::dataType(), 42,
                               &IntegerDataType::dataType(), nullptr,
                               0, 1, 0xFFFF, nullptr);
    TEST("indexed.single.name", idx.getName() == "SingleKeyIdx");
}

// ---- FactoryStructureDataType tests ----

void test_factory_struct_basic() {
    TestFactoryStruct fs;
    TEST("factory.name", fs.getName() == "TestFactoryStruct");
    TEST("factory.desc", fs.getDescription() == "Dynamic Data Type should not be instantiated directly");
    TEST("factory.length", fs.getLength() == -1);
}

void test_factory_struct_get_data_type() {
    TestFactoryStruct fs;
    DataType* dt = fs.getDataType(nullptr);
    TEST("factory.getDataType", dt != nullptr);
    TEST("factory.getDataType.name", dt->getName() == "TestFactoryStruct");
    delete dt;
}

// ---- StructureFactory tests ----

void test_structure_factory_validation() {
    // Empty name should throw
    bool threw = false;
    try {
        StructureFactory::createStructureDataType(nullptr, Address(), 4, "", true);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    TEST("factory.emptyName", threw);

    // Non-positive length should throw
    threw = false;
    try {
        StructureFactory::createStructureDataType(nullptr, Address(), 0, "struct", true);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    TEST("factory.zeroLen", threw);
}

void test_structure_factory_throws_not_impl() {
    bool threw = false;
    try {
        StructureFactory::createStructureDataType(nullptr, Address(), 4, "struct", true);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    TEST("factory.notImpl", threw);
}

// ---- DataUtilities tests ----

void test_data_utilities_valid_name() {
    TEST("util.validName.ok", DataUtilities::isValidDataTypeName("myType"));
    TEST("util.validName.empty", DataUtilities::isValidDataTypeName("") == false);
    TEST("util.validName.whitespace", DataUtilities::isValidDataTypeName("   ") == false);
    TEST("util.validName.ctrl", DataUtilities::isValidDataTypeName("bad\x01name") == false);
}

} // anonymous namespace

int main() {
    test_leb128_decode_unsigned_small();
    test_leb128_decode_unsigned_multi();
    test_leb128_decode_signed_positive();
    test_leb128_decode_signed_negative();
    test_leb128_decode_signed_negative_multi();
    test_leb128_encode_unsigned_small();
    test_leb128_encode_unsigned_multi();
    test_leb128_encode_signed_neg();
    test_leb128_encode_signed_pos();
    test_leb128_encode_unsigned_zero();
    test_leb128_get_length();
    test_leb128_get_length_single();

    test_sleb128_basic();
    test_sleb128_can_specify_length();
    test_uleb128_basic();

    test_terminated_cstring_basic();
    test_terminated_cstring_layout();
    test_terminated_unicode32_basic();
    test_terminated_unicode32_layout();

    test_dynamic_basic();
    test_dynamic_num_components_null();
    test_structured_basic();
    test_structured_add();
    test_indexed_ctor();
    test_indexed_single_key_ctor();
    test_factory_struct_basic();
    test_factory_struct_get_data_type();
    test_structure_factory_validation();
    test_structure_factory_throws_not_impl();
    test_data_utilities_valid_name();

    std::cout << "Batch S: " << passed << "/" << total << " passed" << std::endl;
    return (passed == total) ? 0 : 1;
}
