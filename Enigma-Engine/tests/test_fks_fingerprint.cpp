// test_fks_fingerprint — FunctionFingerprint struct + FunctionFingerprinter::compute

#include <ghidra/FunctionFingerprint.h>
#include <iostream>
#include <cassert>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"PASS: "<<n<<"\n";passed++;} \
  else{std::cout<<"FAIL: "<<n<<"\n";} } while(0)

int main() {
    using namespace ghidra;

    // Test 1: compute with nullptr args returns empty fingerprint
    {
        FunctionFingerprinter fp;
        FunctionFingerprint result = fp.compute(nullptr, nullptr);
        TEST("compute(nullptr,nullptr) v1.fullHash is 0", result.v1.fullHash == 0);
        TEST("compute(nullptr,nullptr) v1.shortHash is 0", result.v1.shortHash == 0);
        TEST("compute(nullptr,nullptr) v1.mnemHash is 0", result.v1.mnemHash == 0);
        TEST("compute(nullptr,nullptr) v1.callHash is 0", result.v1.callHash == 0);
        TEST("compute(nullptr,nullptr) v2.fullHash is 0", result.v2.fullHash == 0);
        TEST("compute(nullptr,nullptr) v2.shortHash is 0", result.v2.shortHash == 0);
        TEST("compute(nullptr,nullptr) v2.mnemHash is 0", result.v2.mnemHash == 0);
        TEST("compute(nullptr,nullptr) v2.callHash is 0", result.v2.callHash == 0);
    }

    // Test 2: default FunctionFingerprint fields are zero
    {
        FunctionFingerprint fp;
        TEST("default v1.fullHash is 0", fp.v1.fullHash == 0);
        TEST("default v1.shortHash is 0", fp.v1.shortHash == 0);
        TEST("default v1.mnemHash is 0", fp.v1.mnemHash == 0);
        TEST("default v1.callHash is 0", fp.v1.callHash == 0);
        TEST("default v2.fullHash is 0", fp.v2.fullHash == 0);
        TEST("default v2.shortHash is 0", fp.v2.shortHash == 0);
        TEST("default v2.mnemHash is 0", fp.v2.mnemHash == 0);
        TEST("default v2.callHash is 0", fp.v2.callHash == 0);
    }

    // Test 3: hasHashes() returns false when all hashes are 0
    {
        FunctionFingerprint fp;
        TEST("hasHashes() false on default struct", fp.hasHashes() == false);
    }

    // Test 4: hasHashes() returns true when at least one hash is non-zero
    {
        FunctionFingerprint fp;
        fp.v1.fullHash = 0xDEADBEEF;
        TEST("hasHashes() true when v1.fullHash set", fp.hasHashes() == true);

        FunctionFingerprint fp2;
        fp2.v2.fullHash = 0xCAFEBABE;
        TEST("hasHashes() true when v2.fullHash set", fp2.hasHashes() == true);
    }

    // Test 5: two identical FunctionFingerprint structs compare equal
    {
        FunctionFingerprint a, b;
        a.v1.fullHash  = 111; a.v1.shortHash = 222; a.v1.mnemHash  = 333; a.v1.callHash  = 444;
        a.v2.fullHash  = 555; a.v2.shortHash = 666; a.v2.mnemHash  = 777; a.v2.callHash  = 888;
        b.v1.fullHash  = 111; b.v1.shortHash = 222; b.v1.mnemHash  = 333; b.v1.callHash  = 444;
        b.v2.fullHash  = 555; b.v2.shortHash = 666; b.v2.mnemHash  = 777; b.v2.callHash  = 888;
        TEST("identical structs compare equal", a == b);
    }

    // Test 6: two different FunctionFingerprint structs compare not-equal
    {
        FunctionFingerprint a, b;
        a.v1.fullHash = 100;
        b.v1.fullHash = 200;
        TEST("different structs compare not-equal", !(a == b));
    }

    // Test 7: V2-only difference makes structs not-equal
    {
        FunctionFingerprint a, b;
        a.v1.fullHash = 100; b.v1.fullHash = 100;
        a.v2.fullHash = 300; b.v2.fullHash = 400;
        TEST("V2-only difference makes not-equal", !(a == b));
    }

    // Test 8: compute with only null function returns empty
    {
        FunctionFingerprinter fp;
        FunctionFingerprint result = fp.compute(nullptr, nullptr);
        TEST("compute null,null hasHashes is false", result.hasHashes() == false);
    }

    std::cout << "\n=== FKS Fingerprint Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";

    return (passed == total) ? 0 : 1;
}
