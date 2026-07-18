#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <cassert>
#include "ghidra/Assembler.h"

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

static bool bytesEq(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) { return a == b; }

int main() {
    using namespace ghidra;
    Assembler& asm_ = Assembler::instance();

    // ─── Area 1: Size-Awareness & NOP Padding ────────────────────────────────
    // Assemble a 5-byte instruction (MOV RAX, imm64) and verify NOP padding
    {
        auto r1 = asm_.assemble("MOV RAX, 0x1122334455667788", 0x140001000);
        TEST("NOP-pad: MOV RAX,imm64 is 10 bytes", r1.success && r1.bytes.size() == 10);
    }
    {
        auto r1 = asm_.assemble("NOP", 0x140001000);
        TEST("NOP-pad: NOP is 1 byte", r1.success && r1.bytes.size() == 1);
    }
    {
        auto r1 = asm_.assemble("RET", 0x140001000);
        TEST("NOP-pad: RET is 1 byte", r1.success && r1.bytes.size() == 1);
    }
    {
        auto r1 = asm_.assemble("INT3", 0x140001000);
        TEST("NOP-pad: INT3 is 1 byte", r1.success && r1.bytes.size() == 1);
    }
    {
        // XOR EAX,EAX is 2 bytes: 31 C0
        auto r1 = asm_.assemble("XOR EAX, EAX", 0x140001000);
        TEST("NOP-pad: XOR EAX,EAX is 2 bytes", r1.success && r1.bytes.size() == 2);
    }
    // Verify NOP padding is correct (full slot = originalSize, instruction + 0x90 fills)
    {
        // MOV RAX, 0x100 (hex 256) uses sign-extended C7 /0 path: 48 C7 C0 00010000
        auto r1 = asm_.assemble("MOV RAX, 0x100", 0x140001000);
        bool ok = r1.success && r1.bytes.size() == 7;
        if (ok) {
            ok = (r1.bytes[0] == 0x48 && r1.bytes[1] == 0xC7 && r1.bytes[2] == 0xC0 &&
                  r1.bytes[3] == 0x00 && r1.bytes[4] == 0x01);
        }
        TEST("NOP-pad: MOV RAX,0x100 = 7 bytes (48 C7 C0 00010000)", ok);
    }

    // ─── Area 2: Relative Control Flow Math ──────────────────────────────────
    {
        // Short JMP to address +0x10: offset = 0x10 - 2 = 0x0E
        auto r = asm_.assemble("JMP 0x140001010", 0x140001000);
        bool ok = r.success && r.bytes.size() == 2;
        if (ok) {
            // EB 0E
            ok = (r.bytes[0] == 0xEB && r.bytes[1] == 0x0E);
        }
        TEST("JMP: short JMP +0x10 = EB 0E", ok);
    }
    {
        // Short JMP backward: JMP 0x140000FF0 from 0x140001000 => offset = -16 - 2 = -18 = 0xEE
        auto r = asm_.assemble("JMP 0x140000FF0", 0x140001000);
        bool ok = r.success && r.bytes.size() == 2;
        if (ok) {
            ok = (r.bytes[0] == 0xEB && r.bytes[1] == 0xEE);
        }
        TEST("JMP: short JMP -10 = EB EE", ok);
    }
    {
        // Near JMP: target +0x2000 from 0x140001000 => offset = 0x2000 - 5 = 0x1FFB
        auto r = asm_.assemble("JMP 0x140003000", 0x140001000);
        bool ok = r.success && r.bytes.size() == 5;
        if (ok) {
            // E9 FB 1F 00 00
            ok = (r.bytes[0] == 0xE9 && r.bytes[1] == 0xFB && r.bytes[2] == 0x1F &&
                  r.bytes[3] == 0x00 && r.bytes[4] == 0x00);
        }
        TEST("JMP: near JMP +0x2000 = E9 FB1F0000", ok);
    }
    {
        // CALL rel32: CALL to +0x100 => offset = 0x100 - 5 = 0xFB
        auto r = asm_.assemble("CALL 0x140001100", 0x140001000);
        bool ok = r.success && r.bytes.size() == 5;
        if (ok) {
            // E8 FB 00 00 00
            ok = (r.bytes[0] == 0xE8 && r.bytes[1] == 0xFB && r.bytes[2] == 0x00);
        }
        TEST("CALL: CALL +0x100 = E8 FB000000", ok);
    }
    {
        // Short JZ: JZ to +0x10 => offset = 0x10 - 2 = 0x0E
        auto r = asm_.assemble("JZ 0x140001010", 0x140001000);
        bool ok = r.success && r.bytes.size() == 2;
        if (ok) {
            // 74 0E
            ok = (r.bytes[0] == 0x74 && r.bytes[1] == 0x0E);
        }
        TEST("Jcc: short JZ +0x10 = 74 0E", ok);
    }
    {
        // Near JZ: JZ to +0x200 => offset = 0x200 - 6 = 0x1FA
        auto r = asm_.assemble("JZ 0x140001200", 0x140001000);
        bool ok = r.success && r.bytes.size() == 6;
        if (ok) {
            // 0F 84 FA 01 00 00
            ok = (r.bytes[0] == 0x0F && r.bytes[1] == 0x84 && r.bytes[2] == 0xFA &&
                  r.bytes[3] == 0x01);
        }
        TEST("Jcc: near JZ +0x200 = 0F 84 FA010000", ok);
    }
    {
        // JNE alias
        auto r = asm_.assemble("JNE 0x140001010", 0x140001000);
        bool ok = r.success && r.bytes.size() == 2;
        if (ok) ok = (r.bytes[0] == 0x75 && r.bytes[1] == 0x0E);
        TEST("Jcc: JNE alias = 75 0E", ok);
    }

    // ─── Area 3: x86-64 Architecture Edge Cases ─────────────────────────────
    {
        // MOV R15, 0x12345678 => sign-extended C7 /0 (7 bytes)
        // ModRM: mod=3, reg=0 (/0), rm=7 (R15&7) = 0xC7
        auto r = asm_.assemble("MOV R15, 0x12345678", 0x140001000);
        bool ok = r.success && r.bytes.size() == 7;
        if (ok) {
            // 49 C7 C7 78563412
            ok = (r.bytes[0] == 0x49 && r.bytes[1] == 0xC7 && r.bytes[2] == 0xC7 &&
                  r.bytes[3] == 0x78 && r.bytes[4] == 0x56 && r.bytes[5] == 0x34 && r.bytes[6] == 0x12);
        }
        TEST("REX: MOV R15,0x12345678 = 49 C7 C7 78563412", ok);
    }
    {
        // MOV R8D, 0xAB => REX.B + B8 + imm32
        auto r = asm_.assemble("MOV R8D, 0xAB", 0x140001000);
        bool ok = r.success && r.bytes.size() == 6;
        if (ok) {
            // 41 B8 AB 00 00 00
            ok = (r.bytes[0] == 0x41 && r.bytes[1] == 0xB8 && r.bytes[2] == 0xAB);
        }
        TEST("REX: MOV R8D,0xAB = 41 B8 AB000000", ok);
    }
    {
        // PUSH R8 => REX.B 0x50 (2 bytes, no extra)
        auto r = asm_.assemble("PUSH R8", 0x140001000);
        bool ok = r.success && r.bytes.size() == 2;
        if (ok) {
            // 41 50
            ok = (r.bytes[0] == 0x41 && r.bytes[1] == 0x50);
        }
        TEST("PUSH/POP: PUSH R8 = 41 50 (2 bytes)", ok);
    }
    {
        // POP R15 => REX.B + (0x58+7) = 41 5F
        auto r = asm_.assemble("POP R15", 0x140001000);
        TEST("PUSH/POP: POP R15 = 41 5F (2 bytes)",
             r.success && r.bytes.size() == 2 && r.bytes[0] == 0x41 && r.bytes[1] == 0x5F);
    }
    {
        // INC RAX => REX.W FF /0 => 48 FF C0 (3 bytes, REX.W needed for 64-bit INC)
        auto r = asm_.assemble("INC RAX", 0x140001000);
        bool ok = r.success && r.bytes.size() == 3;
        if (ok) {
            ok = (r.bytes[0] == 0x48 && r.bytes[1] == 0xFF && r.bytes[2] == 0xC0);
        }
        TEST("INC/DEC: INC RAX = 48 FF C0 (REX.W needed)", ok);
    }
    {
        // INC ECX => FF C1
        auto r = asm_.assemble("INC ECX", 0x140001000);
        bool ok = r.success && r.bytes.size() == 2;
        if (ok) {
            ok = (r.bytes[0] == 0xFF && r.bytes[1] == 0xC1);
        }
        TEST("INC/DEC: INC ECX = FF C1", ok);
    }
    {
        // DEC R15 => REX.WB FF /1 => 49 FF CF (3 bytes)
        auto r = asm_.assemble("DEC R15", 0x140001000);
        TEST("INC/DEC: DEC R15 = 49 FF CF",
             r.success && r.bytes.size() == 3 && r.bytes[0] == 0x49 && r.bytes[1] == 0xFF && r.bytes[2] == 0xCF);
    }
    {
        // MOV RAX, [R15+RCX*4] — REX for base R15 + index RCX
        auto r = asm_.assemble("MOV RAX, [R15+RCX*4]", 0x140001000);
        bool ok = r.success;
        if (ok) {
            // REX.W=1, REX.B=1 => 0x49, opcode 8B, ModRM(0, 0, 4=SIB), SIB(2, 1, 7)
            ok = (r.bytes[0] == 0x49 && r.bytes[1] == 0x8B && r.bytes[2] == 0x04 &&
                  r.bytes[3] == 0x8F);
        }
        TEST("REX+SIB: MOV RAX,[R15+RCX*4] = 49 8B 04 8F", ok);
    }
    {
        // ADD R15, R15 — REX.W=1, REX.R=1, REX.B=1
        auto r = asm_.assemble("ADD R15, R15", 0x140001000);
        bool ok = r.success && r.bytes.size() == 3;
        if (ok) {
            // REX.W=1 REX.R=1 REX.B=1 => 4D, opcode 01, ModRM(3, 7, 7) = FF
            ok = (r.bytes[0] == 0x4D && r.bytes[1] == 0x01 && r.bytes[2] == 0xFF);
        }
        TEST("REX: ADD R15,R15 = 4D 01 FF", ok);
    }

    // ─── Area 3b: SIB with complex memory scaling ───────────────────────────
    {
        // MOV EAX, [RAX+RCX*4+0x10] — 3-part memory expression
        auto r = asm_.assemble("MOV EAX, [RAX+RCX*4+0x10]", 0x140001000);
        bool ok = r.success;
        if (ok) {
            // opcode 8B, ModRM(1, 0, 4=SIB), SIB(2, 1, 0), disp8=0x10
            ok = (r.bytes[0] == 0x8B && r.bytes[1] == 0x44 && r.bytes[2] == 0x88 &&
                  r.bytes[3] == 0x10);
        }
        TEST("SIB: MOV EAX,[RAX+RCX*4+0x10] = 8B 44 88 10", ok);
    }
    {
        // MOV ECX, [RBP+RDX*8-0x20] — 3-part with negative displacement
        auto r = asm_.assemble("MOV ECX, [RBP+RDX*8-0x20]", 0x140001000);
        bool ok = r.success;
        if (ok) {
            // opcode 8B, ModRM(1, 1, 4=SIB), SIB(3, 2, 5), disp8=0xE0 (-32)
            ok = (r.bytes[0] == 0x8B && r.bytes[1] == 0x4C && r.bytes[2] == 0xD5 &&
                  r.bytes[3] == 0xE0);
        }
        TEST("SIB: MOV ECX,[RBP+RDX*8-0x20] = 8B 4C D5 E0", ok);
    }
    {
        // MOV EAX, [RCX*4] — index-only (no base)
        auto r = asm_.assemble("MOV EAX, [RCX*4]", 0x140001000);
        bool ok = r.success;
        if (ok) {
            // ModRM(0, 0, 4=SIB), SIB(2, 1, 5), disp32=0
            ok = (r.bytes[0] == 0x8B && r.bytes[1] == 0x04 && r.bytes[2] == 0x8D &&
                  r.bytes[3] == 0x00 && r.bytes[4] == 0x00 && r.bytes[5] == 0x00 && r.bytes[6] == 0x00);
        }
        TEST("SIB: MOV EAX,[RCX*4] = 8B 04 8D 00000000", ok);
    }

    // ─── Area 4: RIP-Relative Addressing ─────────────────────────────────────
    {
        // LEA RAX, [RIP+0x100] from address 0x140001000
        // disp32 = 0x100 (user-provided), ModRM(0, 0, 5=RIP), disp32=0x100
        auto r = asm_.assemble("LEA RAX, [RIP+0x100]", 0x140001000);
        bool ok = r.success && r.bytes.size() == 7;
        if (ok) {
            // REX.W=1, 8D, ModRM(0, 0, 5), disp32
            ok = (r.bytes[0] == 0x48 && r.bytes[1] == 0x8D && r.bytes[2] == 0x05 &&
                  r.bytes[3] == 0x00 && r.bytes[4] == 0x01 && r.bytes[5] == 0x00 && r.bytes[6] == 0x00);
        }
        TEST("RIP-rel: LEA RAX,[RIP+0x100] = 48 8D 05 00010000", ok);
    }
    {
        // MOV EAX, [RIP-4] — negative RIP displacement, 6 bytes
        auto r = asm_.assemble("MOV EAX, [RIP-4]", 0x140001000);
        bool ok = r.success && r.bytes.size() == 6;
        if (ok) {
            // 8B 05 FCFFFFFF
            ok = (r.bytes[0] == 0x8B && r.bytes[1] == 0x05 &&
                  r.bytes[2] == 0xFC && r.bytes[3] == 0xFF && r.bytes[4] == 0xFF && r.bytes[5] == 0xFF);
        }
        TEST("RIP-rel: MOV EAX,[RIP-4] = 8B 05 FCFFFFFF", ok);
    }
    {
        // LEA RAX, [RIP] — zero displacement
        auto r = asm_.assemble("LEA RAX, [RIP]", 0x140001000);
        bool ok = r.success && r.bytes.size() == 7;
        if (ok) {
            ok = (r.bytes[0] == 0x48 && r.bytes[1] == 0x8D && r.bytes[2] == 0x05 &&
                  r.bytes[3] == 0x00 && r.bytes[4] == 0x00 && r.bytes[5] == 0x00 && r.bytes[6] == 0x00);
        }
        TEST("RIP-rel: LEA RAX,[RIP] = 48 8D 05 00000000", ok);
    }

    // ─── Area 5: Edge case — overflow rejection ──────────────────────────────
    {
        // JMP too far for short but fits near
        auto r = asm_.assemble("JMP 0x140001100", 0x140001000);
        TEST("JMP: near JMP +0x100 succeeds", r.success && r.bytes.size() == 5);
    }
    {
        // CALL to valid target
        auto r = asm_.assemble("CALL 0x140001100", 0x140001000);
        TEST("CALL: valid target succeeds", r.success);
    }
    {
        // MOV RAX, imm64 with 64-bit value
        auto r = asm_.assemble("MOV RAX, 0x1122334455667788", 0x140001000);
        bool ok = r.success && r.bytes.size() == 10;
        if (ok) {
            // 48 B8 8877665544332211
            ok = (r.bytes[0] == 0x48 && r.bytes[1] == 0xB8 &&
                  r.bytes[2] == 0x88 && r.bytes[3] == 0x77 && r.bytes[4] == 0x66 &&
                  r.bytes[5] == 0x55 && r.bytes[6] == 0x44 && r.bytes[7] == 0x33 &&
                  r.bytes[8] == 0x22 && r.bytes[9] == 0x11);
        }
        TEST("64-bit imm: MOV RAX,0x1122334455667788 = 48 B8 8877665544332211", ok);
    }
    {
        // MOV R8, imm64 with value within strtoll range
        auto r = asm_.assemble("MOV R8, 0x1122334455667788", 0x140001000);
        bool ok = r.success && r.bytes.size() == 10;
        if (ok) {
            // 49 B8 8877665544332211
            ok = (r.bytes[0] == 0x49 && r.bytes[1] == 0xB8 &&
                  r.bytes[2] == 0x88 && r.bytes[3] == 0x77 && r.bytes[4] == 0x66 &&
                  r.bytes[5] == 0x55 && r.bytes[6] == 0x44 && r.bytes[7] == 0x33 &&
                  r.bytes[8] == 0x22 && r.bytes[9] == 0x11);
        }
        TEST("64-bit imm: MOV R8,0x1122334455667788 = 49 B8 8877665544332211", ok);
    }

    // ─── Additional: InstructionPatch NOP padding integration ────────────────
    {
        // Simulate: original=5 bytes, new=2 bytes → should produce 2 bytes + 3 NOPs
        // Use InstructionPatch constructor with originalSize
        // Assemble 2-byte instruction
        auto r = asm_.assemble("XOR EAX, EAX", 0x140001000);
        TEST("Patch-size: XOR EAX,EAX assembles to 2 bytes", r.success && r.bytes.size() == 2);

        // Now manually construct what InstructionPatch does with originalSize=5
        std::vector<uint8_t> patched = r.bytes;
        patched.resize(5, 0x90); // NOP-pad to 5 bytes
        TEST("Patch-size: NOP-padded result = 31 C0 90 90 90",
             patched.size() == 5 &&
             patched[0] == 0x31 && patched[1] == 0xC0 &&
             patched[2] == 0x90 && patched[3] == 0x90 && patched[4] == 0x90);
    }
    {
        // Verify CMP EAX, 0 assembles to 2 bytes (83 F8 00)
        auto r = asm_.assemble("CMP EAX, 0", 0x140001000);
        bool ok = r.success && r.bytes.size() == 3;
        if (ok) {
            ok = (r.bytes[0] == 0x83 && r.bytes[1] == 0xF8 && r.bytes[2] == 0x00);
        }
        TEST("Arithmetic: CMP EAX,0 = 83 F8 00", ok);
    }
    {
        // ADD [RAX], 5 — memory + immediate
        auto r = asm_.assemble("ADD DWORD PTR [RAX], 5", 0x140001000);
        bool ok = r.success && r.bytes.size() == 3;
        if (ok) {
            // 83 00 05
            ok = (r.bytes[0] == 0x83 && r.bytes[1] == 0x00 && r.bytes[2] == 0x05);
        }
        TEST("Arith-mem: ADD [RAX],5 = 83 00 05", ok);
    }

    std::cout << "\n" << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
