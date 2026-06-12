/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_n.cpp
/// \brief Tests for W~N: InjectContext, InjectPayload, InjectPayloadSleigh, InjectPayloadSubtypes.
#include <ghidra/InjectContext.h>
#include <ghidra/InjectPayload.h>
#include <ghidra/InjectPayloadSleigh.h>
#include <ghidra/InjectPayloadSubtypes.h>
#include <ghidra/SleighLanguage.h>
#include <ghidra/SleighLanguageDescription.h>
#include <iostream>
#include <string>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

void test_inject_context_default() {
    InjectContext ctx;
    TEST("InjectContext.language.null", ctx.language == nullptr);
    TEST("InjectContext.baseAddr.default", ctx.baseAddr == Address());
    TEST("InjectContext.nextAddr.default", ctx.nextAddr == Address());
    TEST("InjectContext.callAddr.default", ctx.callAddr == Address());
    TEST("InjectContext.refAddr.default", ctx.refAddr == Address());
    TEST("InjectContext.inputlist.empty", ctx.inputlist.empty());
    TEST("InjectContext.output.empty", ctx.output.empty());
}

void test_inject_payload_constants() {
    TEST("InjectPayload.CALLFIXUP_TYPE", InjectPayload::CALLFIXUP_TYPE == 1);
    TEST("InjectPayload.CALLOTHERFIXUP_TYPE", InjectPayload::CALLOTHERFIXUP_TYPE == 2);
    TEST("InjectPayload.CALLMECHANISM_TYPE", InjectPayload::CALLMECHANISM_TYPE == 3);
    TEST("InjectPayload.EXECUTABLEPCODE_TYPE", InjectPayload::EXECUTABLEPCODE_TYPE == 4);
}

void test_inject_payload_parameter() {
    InjectPayload::InjectParameter param("myParam", 4);
    TEST("InjectParam.name", param.getName() == "myParam");
    TEST("InjectParam.size", param.getSize() == 4);
    TEST("InjectParam.index.default", param.getIndex() == 0);
    param.setIndex(2);
    TEST("InjectParam.index.set", param.getIndex() == 2);

    InjectPayload::InjectParameter other("myParam", 4);
    other.setIndex(2);
    TEST("InjectParam.isEquivalent", param.isEquivalent(other));

    InjectPayload::InjectParameter diff("other", 4);
    TEST("InjectParam.notEquivalent", !param.isEquivalent(diff));

    // Default construct + assign
    InjectPayload::InjectParameter def;
    TEST("InjectParam.default.name", def.getName().empty());
    TEST("InjectParam.default.size", def.getSize() == 0);
}

void test_inject_payload_sleigh() {
    InjectPayloadSleigh payload("test_payload", InjectPayload::EXECUTABLEPCODE_TYPE, "test");
    TEST("InjectPayloadSleigh.name", payload.getName() == "test_payload");
    TEST("InjectPayloadSleigh.type", payload.getType() == InjectPayload::EXECUTABLEPCODE_TYPE);
    TEST("InjectPayloadSleigh.source", payload.getSource() == "test");
    TEST("InjectPayloadSleigh.paramShift", payload.getParamShift() == 0);
    TEST("InjectPayloadSleigh.input.empty", payload.getInput().empty());
    TEST("InjectPayloadSleigh.output.empty", payload.getOutput().empty());
    TEST("InjectPayloadSleigh.notError", !payload.isErrorPlaceholder());
    TEST("InjectPayloadSleigh.fallThru", payload.isFallThru());
    TEST("InjectPayloadSleigh.notIncidental", !payload.isIncidentalCopy());
    TEST("InjectPayloadSleigh.releaseParseString", payload.releaseParseString().empty());
}

void test_inject_payload_callfixup() {
    InjectPayloadCallfixup fixup("test_cfixup");
    TEST("InjectPayloadCallfixup.name", fixup.getName() == "test_cfixup");
    TEST("InjectPayloadCallfixup.type", fixup.getType() == InjectPayload::CALLFIXUP_TYPE);
    TEST("InjectPayloadCallfixup.targets.empty", fixup.getTargets().empty());

    fixup.addTarget("target1");
    fixup.addTarget("target2");
    TEST("InjectPayloadCallfixup.targets.count", fixup.getTargets().size() == 2);
    TEST("InjectPayloadCallfixup.targets.0", fixup.getTargets()[0] == "target1");
    TEST("InjectPayloadCallfixup.targets.1", fixup.getTargets()[1] == "target2");
}

void test_inject_payload_callother() {
    InjectPayloadCallother other("test_cofixup");
    TEST("InjectPayloadCallother.name", other.getName() == "test_cofixup");
    TEST("InjectPayloadCallother.type", other.getType() == InjectPayload::CALLOTHERFIXUP_TYPE);
}

void test_inject_payload_jump_assist() {
    InjectPayloadJumpAssist jump("myBase", "jump_assist");
    TEST("InjectPayloadJumpAssist.name", jump.getName() == "jump_assist");
    TEST("InjectPayloadJumpAssist.type", jump.getType() == InjectPayload::EXECUTABLEPCODE_TYPE);
}

void test_inject_payload_segment() {
    InjectPayloadSegment seg("segment_source");
    TEST("InjectPayloadSegment.name", seg.getName() == "segment_source");
    TEST("InjectPayloadSegment.type", seg.getType() == InjectPayload::EXECUTABLEPCODE_TYPE);
    TEST("InjectPayloadSegment.space.default", seg.getSpace() == nullptr);
    TEST("InjectPayloadSegment.farPtr.default", !seg.getSupportsFarPointer());
}

void test_inject_payload_error_types() {
    SleighLanguageDescription desc(
        LanguageID("x86:LE:32:default"), "x86 32-bit",
        Processor("x86"), Endian::LITTLE, Endian::LITTLE,
        32, "default", 1, 0
    );
    SleighLanguage lang(&desc);
    // Just test that error placeholders construct without crashing
    InjectPayloadCallfixupError errFixup(nullptr, "err_fixup");
    TEST("InjectPayloadCallfixupError.name", errFixup.getName() == "err_fixup");
    TEST("InjectPayloadCallfixupError.isError", errFixup.isErrorPlaceholder());

    InjectPayloadCallotherError errOther(nullptr, "err_cofixup");
    TEST("InjectPayloadCallotherError.name", errOther.getName() == "err_cofixup");
    TEST("InjectPayloadCallotherError.isError", errOther.isErrorPlaceholder());
}

} // anonymous namespace

int main() {
    test_inject_context_default();
    test_inject_payload_constants();
    test_inject_payload_parameter();
    test_inject_payload_sleigh();
    test_inject_payload_callfixup();
    test_inject_payload_callother();
    test_inject_payload_jump_assist();
    test_inject_payload_segment();
    test_inject_payload_error_types();

    std::cout << "\n[Batch N] " << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
