/**
 * Enigma Engine - Lang Classes Smoke Test
 * Smoke tests for the model.lang classes ported in W137 (Batch D).
 */
#include <ghidra/GhidraLanguagePropertyKeys.h>
#include <ghidra/OldLanguageMappingService.h>
#include <ghidra/MaskImpl.h>
#include <ghidra/InstructionError.h>
#include <ghidra/InjectPayloadSubtypes.h>
#include <ghidra/InvalidPrototype.h>
#include <ghidra/PrototypeModelMerged.h>
#include <iostream>
#include <cstring>
#include <vector>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

int main() {
    std::cout << "=== Lang Classes Test ===\n";

    TEST("GhidraLanguagePropertyKeys MAXIMUM_INSTRUCTION_LENGTH",
         GhidraLanguagePropertyKeys::MAXIMUM_INSTRUCTION_LENGTH == "maximumInstructionLength");
    TEST("GhidraLanguagePropertyKeys IS_TMS320_FAMILY",
         GhidraLanguagePropertyKeys::IS_TMS320_FAMILY == "isTMS320Family");
    TEST("GhidraLanguagePropertyKeys ENABLE_NO_RETURN_ANALYSIS",
         GhidraLanguagePropertyKeys::ENABLE_NO_RETURN_ANALYSIS == "enableNoReturnAnalysis");
    TEST("GhidraLanguagePropertyKeys MINIMUM_DATA_IMAGE_BASE",
         GhidraLanguagePropertyKeys::MINIMUM_DATA_IMAGE_BASE == "minimumDataImageBase");

    OldLanguageMappingService svc;
    LanguageCompilerSpecPair p1 = OldLanguageMappingService::lookupMagicString("unknown:lang", true);
    TEST("lookupMagicString empty result", !p1.isValid());
    LanguageCompilerSpecPair p2 = OldLanguageMappingService::processXmlLanguageString("x86:LE:32:default");
    TEST("processXmlLanguageString x86:LE:32:default valid", p2.isValid());
    TEST("processXmlLanguageString x86 langID", p2.languageID.getIdAsString() == "x86:LE:32");
    TEST("processXmlLanguageString x86 csID", p2.compilerSpecID.getIdAsString() == "default");
    LanguageCompilerSpecPair p3 = OldLanguageMappingService::processXmlLanguageString("x86:LE:32:default:windows");
    TEST("processXmlLanguageString multi-colon", p3.isValid());
    TEST("processXmlLanguageString empty", !OldLanguageMappingService::processXmlLanguageString("").isValid());

    std::vector<uint8_t> mask = {0xff, 0x0f, 0xf0};
    MaskImpl mi(mask);
    TEST("MaskImpl length", mi.getBytes().size() == 3);
    TEST("MaskImpl toString", mi.toString() == "FF0FF0");

    std::vector<uint8_t> cde = {0xab, 0xcd, 0xef};
    std::vector<uint8_t> res(3, 0);
    mi.applyMask(cde, res);
    TEST("MaskImpl applyMask 0", res[0] == 0xab);
    TEST("MaskImpl applyMask 1", res[1] == 0x0d);
    TEST("MaskImpl applyMask 2", res[2] == 0xe0);

    std::vector<uint8_t> mask2 = {0xff, 0x0f, 0xf0};
    MaskImpl mi2(mask2);
    TEST("MaskImpl equals", mi.equals(mi2.getBytes()));
    std::vector<uint8_t> mask3 = {0xff, 0x0f};
    MaskImpl mi3(mask3);
    TEST("MaskImpl not equals different len", !mi.equals(mi3.getBytes()));
    TEST("MaskImpl not equals null", !mi.equals((const Mask*)nullptr));

    std::vector<uint8_t> tgt = {0xab, 0x0d, 0xe0};
    TEST("MaskImpl equalMaskedValue", mi.equalMaskedValue(cde, tgt));
    std::vector<uint8_t> tgt2 = {0xab, 0x0d, 0xff};
    TEST("MaskImpl not equalMaskedValue", !mi.equalMaskedValue(cde, tgt2));

    std::vector<uint8_t> sub = {0x00, 0x00, 0x00};
    TEST("MaskImpl subMask zero", mi.subMask(sub));
    std::vector<uint8_t> sub2 = {0x00, 0x01, 0x00};
    TEST("MaskImpl subMask partial", mi.subMask(sub2));
    std::vector<uint8_t> notSub = {0xff, 0xff, 0xff};
    TEST("MaskImpl not subMask", !mi.subMask(notSub));

    InjectPayloadCallfixup cf("test.sinc");
    TEST("Callfixup type", cf.getType() == InjectPayload::CALLFIXUP_TYPE);
    TEST("Callfixup name", cf.getName() == "test.sinc");
    TEST("Callfixup empty targets", cf.getTargets().empty());
    cf.addTarget("free");
    cf.addTarget("malloc");
    TEST("Callfixup addTarget", cf.getTargets().size() == 2);
    TEST("Callfixup target 0", cf.getTargets()[0] == "free");

    InjectPayloadCallother co("userop_x");
    TEST("Callother type", co.getType() == InjectPayload::CALLOTHERFIXUP_TYPE);
    TEST("Callother name", co.getName() == "userop_x");

    InjectPayloadJumpAssist ja("base", "test.cs");
    TEST("JumpAssist type", ja.getType() == InjectPayload::EXECUTABLEPCODE_TYPE);

    InjectPayloadSegment seg("test.cs");
    TEST("Segment type", seg.getType() == InjectPayload::EXECUTABLEPCODE_TYPE);
    TEST("Segment space null", seg.getSpace() == nullptr);
    TEST("Segment no far pointer", !seg.getSupportsFarPointer());

    using EET = InstructionError::InstructionErrorType;
    TEST("InstructionError isConflictType DUPLICATE", InstructionError::isConflictType(EET::DUPLICATE));
    TEST("InstructionError isConflictType PARSE", !InstructionError::isConflictType(EET::PARSE));

    InvalidPrototype ip(nullptr);
    TEST("InvalidPrototype length 1", ip.getInstructionLength() == 1);
    TEST("InvalidPrototype delay depth 0", ip.getDelaySlotDepth() == 0);
    TEST("InvalidPrototype mnemonic", ip.getMnemonic() == "BAD-Instruction");
    TEST("InvalidPrototype hasDelaySlots false", !ip.hasDelaySlots());
    TEST("InvalidPrototype isInDelaySlot false", !ip.isInDelaySlot());

    PrototypeModelMerged pmm;
    TEST("PrototypeModelMerged isMerged", pmm.isMerged());
    TEST("PrototypeModelMerged numModels 0", pmm.numModels() == 0);

    std::cout << "=== " << passed << "/" << total << " tests passed ===\n";
    return (passed == total) ? 0 : 1;
}
