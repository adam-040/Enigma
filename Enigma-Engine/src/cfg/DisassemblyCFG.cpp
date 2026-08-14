#include <cfg/DisassemblyCFG.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <set>

namespace cfg {

namespace {

std::string upper(const std::string& s) {
    std::string out = s;
    for (char& c : out)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

} // namespace

const char* edgeKindName(EdgeKind kind) {
    switch (kind) {
    case EdgeKind::Unconditional: return "unconditional";
    case EdgeKind::Conditional:   return "conditional";
    case EdgeKind::Call:          return "call";
    case EdgeKind::Return:        return "return";
    case EdgeKind::Computed:      return "computed";
    case EdgeKind::ComputedCall:  return "computed-call";
    }
    return "unknown";
}

std::vector<int> assignTracks(const std::vector<const CfaEdge*>& edges) {
    const int n = static_cast<int>(edges.size());
    std::vector<int> lanes(n, 0);
    if (n == 0) return lanes;

    // Deterministic processing order independent of caller-provided order.
    // Spanning priority: shorter jumps sort first so they hug the text
    // boundary (inner tracks); long-spanning jumps fall back to the outer
    // tracks left of them.
    std::vector<int> order;
    order.reserve(n);
    for (int i = 0; i < n; ++i) order.push_back(i);
    std::sort(order.begin(), order.end(), [&](int a, int c) {
        const CfaEdge& ea = *edges[a];
        const CfaEdge& ec = *edges[c];
        const int sa = std::min(ea.fromRow, ea.toRow);
        const int sc = std::min(ec.fromRow, ec.toRow);
        const int eaE = std::max(ea.fromRow, ea.toRow);
        const int ecE = std::max(ec.fromRow, ec.toRow);
        const int lena = eaE - sa;
        const int lenc = ecE - sc;
        if (lena != lenc) return lena < lenc; // shorter span first
        if (sa != sc) return sa < sc;
        if (eaE != ecE) return eaE < ecE;
        if (ea.fromRow != ec.fromRow) return ea.fromRow < ec.fromRow;
        return ea.toAddr < ec.toAddr;
    });

    // Interval graph coloring: reuse a track the moment its previous occupant
    // terminated (lastEnd < start), so non-conflicting jumps share columns and
    // only genuinely concurrent spans widen the layout.
    int lastEnd[kCFAMaxTracks] = {-1, -1, -1, -1};
    for (const int idx : order) {
        const CfaEdge& e = *edges[idx];
        const int start = std::min(e.fromRow, e.toRow);
        const int end = std::max(e.fromRow, e.toRow);
        int t = 0;
        while (t < kCFAMaxTracks && lastEnd[t] >= start)
            ++t;
        const int lane = std::min(t, kCFAMaxTracks - 1); // 4+ concurrent: overspill lane
        lanes[idx] = lane;
        lastEnd[lane] = end;
    }
    return lanes;
}

bool DisassemblyCFG::isCallMnemonic(const std::string& mne) {
    const std::string m = upper(mne);
    return m == "CALL" || m == "CALLF" || m == "CALLQ" ||
           m == "CALLW" || m == "CALLD" || m == "CALLT";
}

bool DisassemblyCFG::isReturnMnemonic(const std::string& mne) {
    const std::string m = upper(mne);
    return m == "RET" || m == "RETN" || m == "RETF" ||
           m == "IRET" || m == "IRETD" || m == "IRETQ";
}

bool DisassemblyCFG::isUnconditionalJumpMnemonic(const std::string& mne) {
    const std::string m = upper(mne);
    return m == "JMP" || m == "JMPF";
}

bool DisassemblyCFG::isConditionalJumpMnemonic(const std::string& mne) {
    const std::string m = upper(mne);
    static const char* kConds[] = {
        "JE", "JNE", "JZ", "JNZ", "JA", "JAE", "JB", "JBE",
        "JG", "JGE", "JL", "JLE", "JO", "JNO", "JS", "JNS",
        "JP", "JNP", "JC", "JNC",
        "LOOP", "LOOPE", "LOOPNE", "LOOPZ", "LOOPNZ",
    };
    for (const char* c : kConds) {
        if (m == c) return true;
    }
    return false;
}

bool DisassemblyCFG::parseDirectTarget(const std::string& operands, uint64_t& out) {
    int bracketDepth = 0;
    size_t i = 0;
    const size_t n = operands.size();
    while (i < n) {
        const char c = operands[i];
        if (c == '[') {
            ++bracketDepth;
            ++i;
            continue;
        }
        if (c == ']') {
            if (bracketDepth > 0) --bracketDepth;
            ++i;
            continue;
        }
        if (bracketDepth == 0 && c == '0' && i + 1 < n &&
            (operands[i + 1] == 'x' || operands[i + 1] == 'X')) {
            size_t j = i + 2;
            while (j < n && std::isxdigit(static_cast<unsigned char>(operands[j])))
                ++j;
            if (j > i + 2) {
                out = std::strtoull(operands.substr(i + 2, j - i - 2).c_str(), nullptr, 16);
                return out != 0;
            }
        }
        ++i;
    }
    return false;
}

void DisassemblyCFG::clear() {
    blocks_.clear();
    edges_.clear();
    blockByRow_.clear();
}

void DisassemblyCFG::build(const std::vector<CfgInsn>& insns,
                           const std::vector<uint64_t>& functionEntries) {
    clear();
    if (insns.empty()) return;

    // Address -> instruction index (addresses are sorted within insns).
    std::unordered_map<uint64_t, size_t> addrToIdx;
    addrToIdx.reserve(insns.size());
    for (size_t i = 0; i < insns.size(); ++i) {
        if (insns[i].address != 0)
            addrToIdx[insns[i].address] = i;
    }

    // ---- Pass 1: classify flow, collect edges + leaders ----
    std::set<size_t> leaders;
    leaders.insert(0);
    std::vector<int> edgeAtInsn(insns.size(), -1);

    for (size_t i = 0; i < insns.size(); ++i) {
        const CfgInsn& in = insns[i];
        if (in.mnemonic.empty()) continue;

        EdgeKind kind = EdgeKind::Unconditional;
        bool flow = true;
        if (isCallMnemonic(in.mnemonic)) {
            kind = EdgeKind::Call;
        } else if (isReturnMnemonic(in.mnemonic)) {
            kind = EdgeKind::Return;
        } else if (isUnconditionalJumpMnemonic(in.mnemonic)) {
            kind = EdgeKind::Unconditional;
        } else if (isConditionalJumpMnemonic(in.mnemonic)) {
            kind = EdgeKind::Conditional;
        } else {
            flow = false;
        }
        if (!flow) continue;

        CfaEdge e;
        e.fromAddr = in.address;
        e.fromRow = in.row;
        e.kind = kind;

        if (kind == EdgeKind::Return) {
            e.toAddr = 0;
            e.toRow = -1;
        } else {
            uint64_t target = 0;
            const bool direct = parseDirectTarget(in.operands, target);
            if (direct) {
                e.toAddr = target;
                auto it = addrToIdx.find(target);
                e.toRow = (it != addrToIdx.end()) ? insns[it->second].row : -1;
                if (it != addrToIdx.end())
                    leaders.insert(it->second);
            } else {
                // Indirect / unresolved target.
                e.toAddr = 0;
                e.toRow = -1;
                if (kind == EdgeKind::Call)
                    kind = EdgeKind::ComputedCall;
                else
                    kind = EdgeKind::Computed;
                e.kind = kind;
            }
        }

        edgeAtInsn[i] = static_cast<int>(edges_.size());
        edges_.push_back(e);

        // A jmp/ret/jcc/computed-edge ends its block: the following
        // instruction starts a new one. (Calls keep their fallthrough in the
        // same block, matching the Ghidra basic-block model.)
        if (kind != EdgeKind::Call && kind != EdgeKind::ComputedCall &&
            i + 1 < insns.size())
            leaders.insert(i + 1);
    }

    // ---- Function entries are block leaders ----
    for (uint64_t entry : functionEntries) {
        auto it = addrToIdx.find(entry);
        if (it != addrToIdx.end())
            leaders.insert(it->second);
    }

    // ---- Pass 2: segment blocks at leaders ----
    std::vector<size_t> leaderList(leaders.begin(), leaders.end());
    for (size_t k = 0; k < leaderList.size(); ++k) {
        const size_t start = leaderList[k];
        const size_t end = (k + 1 < leaderList.size()) ? leaderList[k + 1] - 1 : insns.size() - 1;
        CfgBlock b;
        b.index = static_cast<int>(blocks_.size());
        b.startAddr = insns[start].address;
        b.endAddr = insns[end].address;
        b.firstRow = insns[start].row;
        b.lastRow = insns[end].row;
        for (size_t i = start; i <= end; ++i) {
            blockByRow_[insns[i].row] = b.index;
            if (edgeAtInsn[i] >= 0)
                b.outEdges.push_back(edgeAtInsn[i]);
        }
        blocks_.push_back(std::move(b));
    }

    // ---- Pass 3: build-time lane metadata ----
    // Assign the overlap-free lane used by tooling/tests via the same shared
    // sweep the renderer applies per-frame to its filtered subset. Edges with
    // no vertical traversal (returns, unresolved) keep lane 0 as placeholders.
    std::vector<int> resolvedIdx;
    resolvedIdx.reserve(edges_.size());
    for (int i = 0; i < static_cast<int>(edges_.size()); ++i)
        if (!edges_[i].isReturn() && edges_[i].toRow >= 0)
            resolvedIdx.push_back(i);
    std::vector<const CfaEdge*> resolved;
    resolved.reserve(resolvedIdx.size());
    for (const int i : resolvedIdx)
        resolved.push_back(&edges_[i]);
    const std::vector<int> lanes = assignTracks(resolved);
    for (size_t k = 0; k < resolvedIdx.size(); ++k)
        edges_[resolvedIdx[k]].lane = lanes[k];
}

const CfgBlock* DisassemblyCFG::blockAtRow(int row) const {
    auto it = blockByRow_.find(row);
    if (it == blockByRow_.end()) return nullptr;
    return &blocks_[it->second];
}

} // namespace cfg