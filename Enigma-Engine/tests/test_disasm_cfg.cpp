/**
 * Enigma Engine - Control-Flow Graph (DisassemblyCFG) Unit Test
 *
 * Verifies block segmentation (leaders), edge classification, direct-target
 * parsing, computed/indirect handling, return edges, cross-function call
 * edges, back edges (loops), and lane assignment on synthetic instruction
 * streams.
 */
#include <cfg/DisassemblyCFG.h>
#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <vector>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using cfg::CfaEdge;
using cfg::CfgBlock;
using cfg::CfgInsn;
using cfg::DisassemblyCFG;
using cfg::EdgeKind;

namespace {

CfgInsn insn(uint64_t addr, int row, const char* mne, const char* ops = "") {
    CfgInsn i;
    i.address = addr;
    i.row = row;
    i.length = 1;
    i.mnemonic = mne;
    i.operands = ops;
    return i;
}

} // namespace

int main() {
    std::cout << "=== Enigma Engine - DisassemblyCFG Test ===" << std::endl;

    // ---- 1. parseDirectTarget ----
    {
        uint64_t t = 0;
        TEST("direct target '0x1400014b0'", DisassemblyCFG::parseDirectTarget("0x1400014b0", t) && t == 0x1400014b0ULL);
        TEST("direct target ' 0x1400014b0 ' (space padded)", DisassemblyCFG::parseDirectTarget(" 0x1400014b0 ", t) && t == 0x1400014b0ULL);
        TEST("direct target lowercase hex", DisassemblyCFG::parseDirectTarget("0xdeadbeef", t) && t == 0xdeadbeefULL);
        TEST("register operand not a target", !DisassemblyCFG::parseDirectTarget("rax", t));
        TEST("memory operand not a target", !DisassemblyCFG::parseDirectTarget("[rax + 0x140]", t));
        TEST("indirect through pointer table not a target", !DisassemblyCFG::parseDirectTarget("qword ptr [0x1400015e8]", t));
        TEST("empty operands not a target", !DisassemblyCFG::parseDirectTarget("", t));
        TEST("zero target rejected", !DisassemblyCFG::parseDirectTarget("0x0", t));
    }

    // ---- 2. mnemonic classification ----
    {
        TEST("CALL is call", DisassemblyCFG::isCallMnemonic("CALL") && DisassemblyCFG::isCallMnemonic("call"));
        TEST("CALLQ is call", DisassemblyCFG::isCallMnemonic("CALLQ"));
        TEST("JMP unconditional", DisassemblyCFG::isUnconditionalJumpMnemonic("JMP"));
        TEST("JE conditional", DisassemblyCFG::isConditionalJumpMnemonic("JE"));
        TEST("LOOPNE conditional", DisassemblyCFG::isConditionalJumpMnemonic("LOOPNE"));
        TEST("JAE conditional", DisassemblyCFG::isConditionalJumpMnemonic("JAE"));
        TEST("JMP not conditional", !DisassemblyCFG::isConditionalJumpMnemonic("JMP"));
        TEST("RET is return", DisassemblyCFG::isReturnMnemonic("RET") && DisassemblyCFG::isReturnMnemonic("IRETQ"));
        TEST("MOV is nothing", !DisassemblyCFG::isCallMnemonic("MOV") &&
                               !DisassemblyCFG::isReturnMnemonic("MOV") &&
                               !DisassemblyCFG::isConditionalJumpMnemonic("MOV") &&
                               !DisassemblyCFG::isUnconditionalJumpMnemonic("MOV"));
    }

    // ---- 3. diamond: je -> join, jmp -> join ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x100, 0, "CMP", "eax, ebx"),
            insn(0x110, 1, "JE", "0x140"),
            insn(0x120, 2, "MOV", "eax, 1"),
            insn(0x130, 3, "JMP", "0x150"),
            insn(0x140, 4, "MOV", "eax, 2"),
            insn(0x150, 5, "RET"),
        };
        cfg.build(insns, {});

        TEST("diamond: 4 blocks", cfg.blocks().size() == 4);
        TEST("diamond: 3 edges", cfg.edges().size() == 3);
        TEST("diamond: block0 rows 0-1", cfg.blockAtRow(0) && cfg.blockAtRow(0)->lastRow == 1);
        TEST("diamond: block1 rows 2-3", cfg.blockAtRow(2) && cfg.blockAtRow(2)->lastRow == 3);
        TEST("diamond: join block starts at row 4",
             cfg.blockAtRow(4) && cfg.blockAtRow(4)->index != cfg.blockAtRow(3)->index);
        const CfaEdge* je = nullptr;
        const CfaEdge* jmp = nullptr;
        const CfaEdge* ret = nullptr;
        for (const CfaEdge& e : cfg.edges()) {
            if (e.kind == EdgeKind::Conditional) je = &e;
            else if (e.kind == EdgeKind::Unconditional) jmp = &e;
            else if (e.kind == EdgeKind::Return) ret = &e;
        }
        TEST("diamond: je 0x110 -> 0x140", je && je->fromRow == 1 && je->toRow == 4 && je->toAddr == 0x140);
        TEST("diamond: jmp 0x130 -> 0x150", jmp && jmp->fromRow == 3 && jmp->toRow == 5 && jmp->toAddr == 0x150);
        TEST("diamond: ret to exit", ret && ret->toAddr == 0 && ret->toRow == -1 && ret->isReturn());
        TEST("diamond: no cross-block ownership", cfg.blockAtRow(1) == cfg.blockAtRow(0));
        TEST("diamond: gap row has no block", cfg.blockAtRow(99) == nullptr);
    }

    // ---- 4. loop back edge ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x200, 0, "MOV", "ecx, 10"),
            insn(0x210, 1, "ADD", "ecx, -1"),
            insn(0x220, 2, "JNE", "0x210"),
            insn(0x230, 3, "RET"),
        };
        cfg.build(insns, {});
        TEST("loop: 3 blocks", cfg.blocks().size() == 3);
        const CfaEdge* be = nullptr;
        for (const CfaEdge& e : cfg.edges())
            if (e.kind == EdgeKind::Conditional) be = &e;
        TEST("loop: backward edge jne 0x220 -> 0x210", be && be->fromRow == 2 && be->toRow == 1 && be->toAddr == 0x210);
        TEST("loop: back edge drawn upward", be && be->fromRow > be->toRow);
        TEST("loop: body block contains both rows", cfg.blockAtRow(1) == cfg.blockAtRow(2));
    }

    // ---- 5. call + cross-function target ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x100, 0, "CALL", "0x300"),
            insn(0x110, 1, "MOV", "eax, 0"),
            insn(0x120, 2, "RET"),
            insn(0x300, 3, "MOV", "ecx, 7"),
            insn(0x310, 4, "RET"),
        };
        cfg.build(insns, {0x100, 0x300});
        TEST("call: 2 blocks (call keeps fallthrough)", cfg.blocks().size() == 2);
        const CfgBlock* b0 = cfg.blockAtRow(0);
        TEST("call: caller block spans call..ret", b0 && b0->firstRow == 0 && b0->lastRow == 2);
        const CfaEdge* call = nullptr;
        for (const CfaEdge& e : cfg.edges())
            if (e.kind == EdgeKind::Call) call = &e;
        TEST("call: call 0x100 -> 0x300 cross-function", call && call->fromRow == 0 && call->toRow == 3 && call->toAddr == 0x300);
        TEST("call: callee entry is its own block", cfg.blockAtRow(3) != b0);
        TEST("call: caller has 2 outgoing edges", b0 && b0->outEdges.size() == 2);
        TEST("call: resolved edge gets lane 0", call && call->lane == 0);
    }

    // ---- 6. computed (indirect) edges ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x400, 0, "JMP", "rax"),
            insn(0x410, 1, "NOP"),
            insn(0x420, 2, "CALL", "[rbx]"),
            insn(0x430, 3, "RET"),
        };
        cfg.build(insns, {});
        TEST("computed: 2 blocks", cfg.blocks().size() == 2);
        const CfaEdge* j = nullptr;
        const CfaEdge* c = nullptr;
        for (const CfaEdge& e : cfg.edges()) {
            if (e.kind == EdgeKind::Computed) j = &e;
            else if (e.kind == EdgeKind::ComputedCall) c = &e;
        }
        TEST("computed: jmp rax unresolved", j && j->toAddr == 0 && j->toRow == -1 && j->isComputed());
        TEST("computed: call [rbx] unresolved", c && c->toAddr == 0 && c->isComputed());
        TEST("computed: jmp splits block", cfg.blockAtRow(1) && cfg.blockAtRow(1) != cfg.blockAtRow(0));
        TEST("computed: call keeps fallthrough", cfg.blockAtRow(1) == cfg.blockAtRow(2));
    }

    // ---- 7. nested conditionals ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x500, 0, "TEST", "eax, eax"),
            insn(0x510, 1, "JE", "0x560"),
            insn(0x520, 2, "TEST", "ebx, ebx"),
            insn(0x530, 3, "JNE", "0x550"),
            insn(0x540, 4, "JMP", "0x560"),
            insn(0x550, 5, "MOV", "eax, 3"),
            insn(0x560, 6, "MOV", "eax, 4"),
            insn(0x570, 7, "RET"),
        };
        cfg.build(insns, {});
        TEST("nested: 5 blocks", cfg.blocks().size() == 5);
        TEST("nested: inner jne targets 0x550 row 5",
             [&]() {
                 for (const CfaEdge& e : cfg.edges())
                     if (e.kind == EdgeKind::Conditional && e.toAddr == 0x550 && e.fromAddr == 0x530)
                         return e.toRow == 5;
                 return false;
             }());
        TEST("nested: outer je targets join row 6",
             [&]() {
                 for (const CfaEdge& e : cfg.edges())
                     if (e.kind == EdgeKind::Conditional && e.fromAddr == 0x510)
                         return e.toRow == 6 && e.toAddr == 0x560;
                 return false;
             }());
        TEST("nested: jmp block single edge",
             [&]() {
                 const CfgBlock* b = cfg.blockAtRow(4);
                 return b && b->outEdges.size() == 1;
             }());
    }

    // ---- 8. function entry splits a stream ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x5f0, 0, "MOV", "eax, 1"),
            insn(0x600, 1, "CMP", "eax, 2"),
            insn(0x610, 2, "RET"),
        };
        cfg.build(insns, {0x600});
        TEST("entry: 2 blocks", cfg.blocks().size() == 2);
        TEST("entry: stream start is a leader", cfg.blockAtRow(0) != cfg.blockAtRow(1));
        TEST("entry: entry address starts block 1", cfg.blockAtRow(1) && cfg.blockAtRow(1)->startAddr == 0x600);
    }

    // ---- 9. jump target out of the instruction list ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x700, 0, "JMP", "0x900"),
            insn(0x710, 1, "RET"),
        };
        cfg.build(insns, {});
        TEST("out-of-list: edge keeps target address", cfg.edges().size() == 2);
        const CfaEdge* j = nullptr;
        for (const CfaEdge& e : cfg.edges())
            if (e.kind == EdgeKind::Unconditional) j = &e;
        TEST("out-of-list: resolved with toRow -1", j && j->resolved() && j->toRow == -1 && j->toAddr == 0x900);
    }

    // ---- 10. empty input ----
    {
        DisassemblyCFG cfg;
        cfg.build({}, {});
        TEST("empty: no blocks", cfg.empty() && cfg.blocks().empty() && cfg.edges().empty());
        TEST("empty: blockAtRow null", cfg.blockAtRow(0) == nullptr);
    }

    // ---- 11. lane separation for multi-successor blocks ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0xb00, 0, "CALL", "0xb40"),
            insn(0xb10, 1, "MOV", "eax, 1"),
            insn(0xb20, 2, "JE", "0xb50"),
            insn(0xb30, 3, "RET"),
            insn(0xb40, 4, "RET"),
            insn(0xb50, 5, "RET"),
        };
        cfg.build(insns, {0xb00, 0xb40});
        const CfaEdge* call = nullptr;
        const CfaEdge* je = nullptr;
        for (const CfaEdge& e : cfg.edges()) {
            if (e.kind == EdgeKind::Call) call = &e;
            else if (e.kind == EdgeKind::Conditional) je = &e;
        }
        const CfgBlock* b0 = cfg.blockAtRow(0);
        TEST("lanes: caller block owns both edges", b0 && b0->outEdges.size() == 2);
        TEST("lanes: distinct lanes for call + jcc", call && je && call->lane != je->lane);
        // Spanning priority: the shorter jcc (rows 2..5, span 3) hugs the text
        // boundary while the longer call (rows 0..4, span 4) pushes out.
        TEST("lanes: shorter-spanning jcc keeps the inner lane",
             call && je && je->lane == 0 && call->lane > je->lane);
    }

    // ---- 12. edgeKindName ----
    {
        TEST("edgeKindName call", std::string(cfg::edgeKindName(EdgeKind::Call)) == "call");
        TEST("edgeKindName computed-call", std::string(cfg::edgeKindName(EdgeKind::ComputedCall)) == "computed-call");
        TEST("edgeKindName return", std::string(cfg::edgeKindName(EdgeKind::Return)) == "return");
    }

    // ---- 13. dynamic track assignment (global sweep) ----
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0xc00, 0, "CMP", "eax, ebx"),
            insn(0xc10, 1, "JNE", "0xcf0"),
            insn(0xc20, 2, "MOV", "eax, 1"),
            insn(0xc30, 3, "CMP", "eax, 0"),
            insn(0xc40, 4, "JNE", "0xd00"),
            insn(0xc50, 5, "RET"),
            insn(0xcf0, 10, "MOV", "eax, 2"),
            insn(0xd00, 11, "MOV", "eax, 3"),
        };
        cfg.build(insns, {});
        // jne rows 1->10 (span 1..10) and jne rows 4->11 (span 4..11) overlap.
        const CfaEdge* a = nullptr;
        const CfaEdge* b = nullptr;
        for (const CfaEdge& e : cfg.edges()) {
            if (e.kind == EdgeKind::Conditional && e.fromRow == 1) a = &e;
            else if (e.kind == EdgeKind::Conditional && e.fromRow == 4) b = &e;
        }
        TEST("tracks: overlapping spans get distinct lanes", a && b && a->lane != b->lane);
        TEST("tracks: shorter-spanning edge keeps inner lane", a && b && b->lane < a->lane && b->lane == 0);
        TEST("tracks: lanes stay within the track cap",
             a && b && a->lane >= 0 && a->lane < 4 && b->lane >= 0 && b->lane < 4);
    }
    {
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0xe00, 0, "JMP", "0xe20"),
            insn(0xe10, 1, "RET"),
            insn(0xe20, 2, "MOV", "eax, 1"),
            insn(0xe30, 3, "JMP", "0xe50"),
            insn(0xe40, 4, "RET"),
            insn(0xe50, 5, "MOV", "eax, 2"),
        };
        cfg.build(insns, {});
        // jmp rows 0->2 (span 0..2) and jmp rows 3->5 (span 3..5) are disjoint.
        const CfaEdge* a = nullptr;
        const CfaEdge* b = nullptr;
        for (const CfaEdge& e : cfg.edges()) {
            if (e.kind == EdgeKind::Unconditional && e.fromRow == 0) a = &e;
            else if (e.kind == EdgeKind::Unconditional && e.fromRow == 3) b = &e;
        }
        TEST("tracks: disjoint spans reuse the inner lane", a && b && a->lane == b->lane && a->lane == 0);
        TEST("tracks: single-edge blocks get lane 0", a && a->lane == 0);
    }
    {
        // Spanning priority + recycling: the two short mutually-exclusive jumps
        // must share the inner lane 0 (column reused once the span ends), while
        // the long jump overlapping both is pushed out to lane 1.
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0x100, 0, "JMP", "0x1a0"),
            insn(0x110, 1, "NOP"),
            insn(0x120, 2, "JNE", "0x140"),
            insn(0x130, 3, "NOP"),
            insn(0x140, 4, "MOV", "eax, 1"),
            insn(0x150, 5, "NOP"),
            insn(0x160, 6, "JNE", "0x180"),
            insn(0x170, 7, "NOP"),
            insn(0x180, 8, "MOV", "eax, 2"),
            insn(0x190, 9, "NOP"),
            insn(0x1a0, 10, "MOV", "eax, 3"),
        };
        cfg.build(insns, {});
        const CfaEdge* jmp = nullptr;
        const CfaEdge* j1 = nullptr;
        const CfaEdge* j2 = nullptr;
        for (const CfaEdge& e : cfg.edges()) {
            if (e.kind == EdgeKind::Unconditional && e.fromRow == 0) jmp = &e;
            else if (e.kind == EdgeKind::Conditional && e.fromRow == 2) j1 = &e;
            else if (e.kind == EdgeKind::Conditional && e.fromRow == 6) j2 = &e;
        }
        // j1 (rows 2..4) and j2 (rows 6..8) are mutually exclusive: same track.
        TEST("tracks: exclusive short spans share the inner lane",
             j1 && j2 && j1->lane == 0 && j2->lane == 0);
        // The long jmp (rows 0..10) overlaps both short ones: outer lane, and
        // strictly further from the text than every short jump it contains.
        TEST("tracks: long overlapping span pushed to outer lane",
             jmp && jmp->lane == 1 && jmp->lane > j1->lane && jmp->lane > j2->lane);
        TEST("tracks: all lanes within cap", jmp && j1 && j2 &&
             jmp->lane >= 0 && jmp->lane < 4 && j1->lane >= 0 && j1->lane < 4 &&
             j2->lane >= 0 && j2->lane < 4);
    }
    {
        // assignTracks is the shared per-subset reallocation the renderer calls
        // on each viewport; it must be deterministic regardless of input order.
        DisassemblyCFG cfg;
        std::vector<CfgInsn> insns = {
            insn(0xf00, 0, "JNE", "0xfc0"),
            insn(0xf10, 1, "MOV", "eax, 1"),
            insn(0xf20, 2, "JMP", "0xfd0"),
            insn(0xf30, 3, "NOP"),
            insn(0xf40, 4, "JNE", "0xfe0"),
            insn(0xf50, 5, "RET"),
            insn(0xfc0, 10, "MOV", "eax, 2"),
            insn(0xfd0, 11, "MOV", "eax, 3"),
            insn(0xfe0, 12, "MOV", "eax, 4"),
        };
        cfg.build(insns, {});
        std::vector<const CfaEdge*> fwd, rev;
        for (const CfaEdge& e : cfg.edges())
            if (!e.isReturn()) { fwd.push_back(&e); rev.push_back(&e); }
        std::reverse(rev.begin(), rev.end());
        const std::vector<int> lf = cfg::assignTracks(fwd);
        const std::vector<int> lr = cfg::assignTracks(rev);
        // Order-independence: the lane ASSIGNED TO A GIVEN EDGE must not depend
        // on the order the edges arrived in, so compare per-edge-pointer.
        std::map<const CfaEdge*, int> mf, mr;
        for (size_t k = 0; k < fwd.size(); ++k) mf[fwd[k]] = lf[k];
        for (size_t k = 0; k < rev.size(); ++k) mr[rev[k]] = lr[k];
        TEST("tracks: assignTracks is order-independent", mf.size() == mr.size() && mf == mr);
        const bool withinCap = [&]() {
            for (const int l : lf) if (l < 0 || l >= cfg::kCFAMaxTracks) return false;
            return true;
        }();
        TEST("tracks: assignTracks lanes within cap", withinCap);
    }

    std::cout << "=== DisassemblyCFG: " << passed << "/" << total << " passed ===" << std::endl;
    return passed == total ? 0 : 1;
}