#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

// Control-flow graph model for the disassembly view.
//
// Pure engine type (no Qt dependency) so it can be unit-tested with a plain
// C++ test binary and reused by the future Function Graph / analysis tooling.
//
// Input is the exact instruction list the view renders (address, model row,
// mnemonic, operand text). The builder classifies flow via mnemonics and
// resolves direct targets from the operand text; indirect targets become
// Computed/ComputedCall edges. Blocks are segmented by "leaders": the first
// instruction, function entries, the instruction after any control-flow
// instruction, and every direct branch/call target.

namespace cfg {

struct CfgInsn {
    uint64_t address = 0; // byte address
    int row = -1;         // model row index of this instruction
    int length = 0;       // encoded length in bytes
    std::string mnemonic; // e.g. "JMP", "CALL", "JE"
    std::string operands; // raw operand text
};

enum class EdgeKind : uint8_t {
    Unconditional, // jmp target
    Conditional,   // jcc/loop target
    Call,          // direct call target
    Return,        // ret -> exit
    Computed,      // indirect jump (unknown target)
    ComputedCall,  // indirect call (unknown target)
};

const char* edgeKindName(EdgeKind kind);

// Hard upper bound on drawing lanes. Edge overlap beyond this count shares
// the outermost lane rather than overflowing the gutter.
constexpr int kCFAMaxTracks = 4;

struct CfaEdge;

// Greedy global track assignment over an arbitrary subset of edges. Returns a
// per-index lane in [0, kCFAMaxTracks) such that two edges whose row-spans
// overlap never share a lane (their vertical lines never share an X). The
// result is deterministic and independent of input order (edges are sorted
// internally by span start, span end, source row, then target address).
// Recompute this over the *filtered* subset the renderer actually draws so
// that only live edges compete for tracks - this is what keeps the margin
// narrow and free of clutter.
std::vector<int> assignTracks(const std::vector<const CfaEdge*>& edges);

struct CfaEdge {
    uint64_t fromAddr = 0; // address of the flow instruction
    uint64_t toAddr = 0;   // target address; 0 = exit / unresolved
    int fromRow = -1;      // model row of the flow instruction
    int toRow = -1;        // model row of the target; -1 = exit/unresolved/out-of-range
    EdgeKind kind = EdgeKind::Unconditional;
    int lane = 0; // overlap-free drawing lane (0..3)

    bool isReturn() const      { return kind == EdgeKind::Return; }
    bool isComputed() const    { return kind == EdgeKind::Computed || kind == EdgeKind::ComputedCall; }
    bool resolved() const      { return toAddr != 0 && !isReturn(); }
};

struct CfgBlock {
    uint64_t startAddr = 0; // address of first instruction
    uint64_t endAddr = 0;   // address of last instruction
    int firstRow = -1;      // model row of first instruction
    int lastRow = -1;       // model row of last instruction
    int index = -1;
    std::vector<int> outEdges; // indices into DisassemblyCFG::edges()
};

class DisassemblyCFG {
public:
    void build(const std::vector<CfgInsn>& insns, const std::vector<uint64_t>& functionEntries);
    void clear();

    const std::vector<CfgBlock>& blocks() const { return blocks_; }
    const std::vector<CfaEdge>& edges() const { return edges_; }
    bool empty() const { return blocks_.empty(); }

    const CfgBlock* blockAtRow(int row) const;

    static bool isCallMnemonic(const std::string& mne);
    static bool isReturnMnemonic(const std::string& mne);
    static bool isUnconditionalJumpMnemonic(const std::string& mne);
    static bool isConditionalJumpMnemonic(const std::string& mne);
    // Parses the first top-level "0x..." literal in the operand text. Returns
    // false for indirect forms (registers / memory operands like "[rax]").
    static bool parseDirectTarget(const std::string& operands, uint64_t& out);

private:
    std::vector<CfgBlock> blocks_;
    std::vector<CfaEdge> edges_;
    std::unordered_map<int, int> blockByRow_; // model row -> block index
};

} // namespace cfg