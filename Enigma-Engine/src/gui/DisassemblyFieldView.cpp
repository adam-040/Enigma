#include "DisassemblyFieldView.h"
#include "EditorTheme.h"
#include "SelectionManager.h"
#include <ghidra/ProgramDB.h>
#include <ghidra/DecompInterface.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/patch/PatchManager.h>
#include <ghidra/patch/Patch.h>
#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QWheelEvent>
#include <QScrollBar>
#include <QApplication>
#include <QClipboard>
#include <QMenu>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QEasingCurve>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <limits>

namespace {
// Euclidean distance from point p to segment ab.
double pointSegDist(const QPoint& p, const QPoint& a, const QPoint& b) {
    const double ax = a.x(), ay = a.y();
    const double bx = b.x(), by = b.y();
    const double px = p.x(), py = p.y();
    const double dx = bx - ax, dy = by - ay;
    const double len2 = dx * dx + dy * dy;
    if (len2 < 1e-12) return std::hypot(px - ax, py - ay);
    double t = ((px - ax) * dx + (py - ay) * dy) / len2;
    t = std::clamp(t, 0.0, 1.0);
    return std::hypot(px - (ax + t * dx), py - (ay + t * dy));
}
} // namespace

DisassemblyFieldView::DisassemblyFieldView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    setFont(EditorTheme::baseFont());
    setFocusPolicy(Qt::StrongFocus);
    setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    caretBlinkTimer_ = new QTimer(this);
    caretBlinkTimer_->setInterval(qMax(100, QApplication::cursorFlashTime() / 2));
    connect(caretBlinkTimer_, &QTimer::timeout, this, [this]() {
        if (hasFocus()) {
            caretVisible_ = !caretVisible_;
            viewport()->update();
        }
    });
    caretBlinkTimer_->start();
    viewport()->setMouseTracking(true);
}

void DisassemblyFieldView::setProgram(ghidra::ProgramDB* program) {
    program_ = program;
    indexBuilt_ = false;
    fallbackLines_.clear();
}

void DisassemblyFieldView::setDecompInterface(ghidra::DecompInterface* decomp) {
    decomp_ = decomp;
    indexBuilt_ = false;
    fallbackLines_.clear();
}

void DisassemblyFieldView::setPatchManager(ghidra::patch::PatchManager* patchMgr) {
    patchMgr_ = patchMgr;
    viewport()->update();
}

void DisassemblyFieldView::setShowBytes(bool show) {
    if (showBytes_ == show) return;
    showBytes_ = show;
    if (indexBuilt_) {
        invalidateCache();
    } else {
        for (auto& fl : fallbackLines_)
            buildTokensForFallback(fl);
        updateScrollBars();
        viewport()->update();
    }
}

void DisassemblyFieldView::showDisassembly(const QString& text) {
    fallbackText_ = text;
    fallbackLines_.clear();
    indexBuilt_ = false;

    QString expanded = text;
    expanded.replace(QLatin1Char('\t'), QString(8, QLatin1Char(' ')));
    QStringList rawLines = expanded.split(QLatin1Char('\n'));

    fallbackLines_.reserve(rawLines.size());
    for (const QString& rawLine : rawLines) {
        FallbackLine fl;
        parseFallbackLine(rawLine, fl);
        buildTokensForFallback(fl);
        fallbackLines_.push_back(std::move(fl));
    }

    currentRow_ = 0;
    currentAddr_ = 0;
    anchor_ = caret_ = {0, 0};
    selecting_ = false;
    dragging_ = false;
    selectedToken_ = {};
    highlightWord_.clear();
    highlightKind_ = TokenKind::Plain;
    currentSelection_ = {};
    maxColsSeen_ = 0;
    horizontalScrollBar()->setValue(0);
    verticalScrollBar()->setValue(0);
    updateScrollBars();
    viewport()->update();
}

void DisassemblyFieldView::buildFullIndex() {
    if (!program_ || !decomp_ || !decomp_->isOpen()) {
        indexBuilt_ = false;
        return;
    }
    try {
        model_.buildIndex(program_, decomp_);
    } catch (const std::exception& e) {
        std::cerr << "[DisassemblyFieldView] buildIndex crashed: " << e.what() << std::endl;
        model_.clear();
    } catch (...) {
        std::cerr << "[DisassemblyFieldView] buildIndex crashed: unknown exception" << std::endl;
        model_.clear();
    }
    indexBuilt_ = model_.rowCount() > 0;
    fallbackLines_.clear();
    decodedCache_.clear();
    buildCFG();
    currentRow_ = 0;
    currentAddr_ = 0;
    anchor_ = caret_ = {0, 0};
    selecting_ = false;
    dragging_ = false;
    selectedToken_ = {};
    highlightWord_.clear();
    highlightKind_ = TokenKind::Plain;
    currentSelection_ = {};
    maxColsSeen_ = 0;
    horizontalScrollBar()->setValue(0);
    verticalScrollBar()->setValue(0);
    updateScrollBars();
    viewport()->update();
}

void DisassemblyFieldView::seekToAddress(uint64_t addr) {
    if (!indexBuilt_ && fallbackLines_.empty())
        return;
    seek(addr);
}

int DisassemblyFieldView::lineCount() const {
    if (indexBuilt_) return model_.rowCount();
    return static_cast<int>(fallbackLines_.size());
}

int DisassemblyFieldView::rows() const {
    return lineCount();
}

int DisassemblyFieldView::rowCount() const {
    return lineCount();
}

std::pair<uint64_t, uint64_t> DisassemblyFieldView::visibleAddressRange() const {
    int n = lineCount();
    if (n == 0) return {0, 0};
    int cellH = EditorTheme::cellHeight();
    int scrollY = verticalScrollBar()->value();
    int vpH = viewport()->height();
    int first = std::min(scrollY / cellH, n - 1);
    int last = std::min((scrollY + vpH) / cellH, n - 1);
    uint64_t a = (indexBuilt_ ? model_.rowToAddress(first) : fallbackLines_[first].addr);
    uint64_t b = (indexBuilt_ ? model_.rowToAddress(last) : fallbackLines_[last].addr);
    return {a, b};
}

int DisassemblyFieldView::maxContentCols() const {
    if (!indexBuilt_) {
        int m = 0;
        for (const auto& fl : fallbackLines_)
            m = std::max(m, fl.totalCols);
        return m;
    }
    return maxColsSeen_;
}

uint64_t DisassemblyFieldView::addressAtCurrentRow() const {
    if (indexBuilt_) {
        const DisasmRow* r = model_.rowAt(currentRow_);
        if (r && r->kind == DisasmRow::Kind::Instruction) return r->address;
        return 0;
    }
    if (currentRow_ >= 0 && currentRow_ < static_cast<int>(fallbackLines_.size()))
        return fallbackLines_[currentRow_].addr;
    return 0;
}

void DisassemblyFieldView::syncCurrentAddress() {
    uint64_t addr = addressAtCurrentRow();
    if (addr != 0 && addr != currentAddr_) {
        currentAddr_ = addr;
        emit cursorAddressChanged(addr);
    } else if (addr == 0) {
        currentAddr_ = 0;
    }
}

void DisassemblyFieldView::seek(uint64_t addr) {
    int row = -1;
    if (indexBuilt_) {
        row = model_.addressToRow(addr);
        if (row < 0) {
            // nearest instruction at or below addr
            int lo = 0, hi = model_.rowCount() - 1, best = -1;
            while (lo <= hi) {
                int mid = lo + (hi - lo) / 2;
                const DisasmRow* r = model_.rowAt(mid);
                if (!r) break;
                if (r->address <= addr) {
                    best = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            // best = last row with address <= addr; walk backward to an instruction row.
            // Note: a FunctionHeader shares its address with the instruction that follows it.
            while (best >= 0) {
                const DisasmRow* r = model_.rowAt(best);
                if (!r) break;
                if (r->kind == DisasmRow::Kind::Instruction) {
                    row = best;
                    break;
                }
                if (r->kind == DisasmRow::Kind::FunctionHeader && best + 1 < model_.rowCount()) {
                    const DisasmRow* next = model_.rowAt(best + 1);
                    if (next && next->kind == DisasmRow::Kind::Instruction && next->address <= addr) {
                        row = best + 1;
                        break;
                    }
                }
                --best;
            }
            if (row < 0 && model_.rowCount() > 0) row = 0;
        }
    } else {
        for (int i = 0; i < static_cast<int>(fallbackLines_.size()); ++i) {
            if (fallbackLines_[i].addr != 0 && fallbackLines_[i].addr <= addr)
                row = i;
            else if (fallbackLines_[i].addr > addr)
                break;
        }
        if (row < 0 && !fallbackLines_.empty()) row = 0;
    }
    if (row < 0) return;

    currentRow_ = row;
    currentAddr_ = (indexBuilt_ ? model_.rowToAddress(row) : fallbackLines_[row].addr);
    anchor_ = caret_ = {row, 0};
    selectedToken_ = {};
    highlightWord_.clear();
    highlightKind_ = TokenKind::Plain;
    ensureVisible(row);
    viewport()->update();
}

void DisassemblyFieldView::invalidateCache() {
    decodedCache_.clear();
    maxColsSeen_ = 0;
    buildCFG();
    updateScrollBars();
    viewport()->update();
}

void DisassemblyFieldView::invalidateRange(uint64_t start, uint64_t end) {
    for (auto it = decodedCache_.begin(); it != decodedCache_.end();) {
        const DecodedInstruction& inst = it->second;
        uint64_t a = inst.address;
        uint64_t len = inst.length > 0 ? static_cast<uint64_t>(inst.length) : 1;
        if (a < end && a + len > start)
            it = decodedCache_.erase(it);
        else
            ++it;
    }
    maxColsSeen_ = 0;
    buildCFG();
    updateScrollBars();
    viewport()->update();
}

void DisassemblyFieldView::buildCFG() {
    cfg_.clear();
    cfgValid_ = false;
    selectedEdge_ = nullptr; // edges are recreated below; drop stale highlight
    scopeLanes_.clear(); // lane map is tied to the fresh edge set
    scopeLanesStart_ = scopeLanesEnd_ = 0;
    cfaDrawValid_ = false; // any rebuild invalidates the render cache
    cfaDrawList_.clear();
    funcStarts_.clear();
    if (!indexBuilt_ || !program_) return;

    try {
        std::vector<cfg::CfgInsn> insns;
        std::vector<uint64_t> entries;
        insns.reserve(model_.totalInstructions());
        for (int r = 0; r < model_.rowCount(); ++r) {
            const DisasmRow* row = model_.rowAt(r);
            if (!row) continue;
            if (row->kind == DisasmRow::Kind::FunctionHeader) {
                entries.push_back(row->address);
                continue;
            }
            if (row->kind != DisasmRow::Kind::Instruction) continue;
            const DecodedInstruction* inst = decodedInstruction(row->address);
            cfg::CfgInsn ci;
            ci.address = row->address;
            ci.row = r;
            ci.length = row->length;
            if (inst) {
                ci.mnemonic = inst->mnemonic.toStdString();
                ci.operands = inst->operands.toStdString();
            }
            insns.push_back(std::move(ci));
        }
        std::sort(entries.begin(), entries.end());
        entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
        cfg_.build(insns, entries);
        cfgValid_ = !cfg_.empty();
        funcStarts_ = std::move(entries);
        funcEndMax_ = model_.rowCount() > 0 ? model_.rowToAddress(model_.rowCount() - 1) : 0;
    } catch (const std::exception& e) {
        std::cerr << "[buildCFG] crashed: " << e.what() << std::endl;
        cfg_.clear();
        cfgValid_ = false;
    } catch (...) {
        std::cerr << "[buildCFG] crashed: unknown exception" << std::endl;
        cfg_.clear();
        cfgValid_ = false;
    }
}

int DisassemblyFieldView::laneX(int lane) {
    return kCfaLaneInset - lane * kCfaNestStep; // 42, 32, 22, 12 for defaults
}

void DisassemblyFieldView::funcRangeFor(uint64_t addr, uint64_t& start, uint64_t& end) const {
    // Intra-function scope: no known boundaries => unbounded (whole document).
    if (funcStarts_.empty()) {
        start = 0;
        end = std::numeric_limits<uint64_t>::max();
        return;
    }
    auto it = std::upper_bound(funcStarts_.begin(), funcStarts_.end(), addr);
    if (it == funcStarts_.begin()) { // before the first function entry
        start = 0;
        end = funcStarts_.front() - 1;
        return;
    }
    --it;
    start = *it;
    const auto nxt = it + 1;
    end = (nxt != funcStarts_.end()) ? (*nxt - 1) : funcEndMax_;
}

void DisassemblyFieldView::rebuildCfaDrawList(int firstRow, int lastRow) {
    cfaDrawList_.clear();
    cfaWindowFirst_ = firstRow;
    cfaWindowLast_ = lastRow;
    if (!cfgValid_) {
        cfaDrawValid_ = true;
        return;
    }

    // 1) Intra-function scope: the function centered in the viewport.
    const int midRow = (firstRow + lastRow) / 2;
    uint64_t sStart = 0, sEnd = 0;
    funcRangeFor(model_.rowToAddress(midRow), sStart, sEnd);
    cfaScopeStart_ = sStart;
    cfaScopeEnd_ = sEnd;

    // 2a) Function-scope track lifetime & recycling: allocate lanes ONCE for
    // every intra-function jump (spanning priority - shorter jumps hug the
    // text, longer ones push out), keyed to the function range so lanes stay
    // rock-stable while scrolling inside one function. Columns are recycled
    // immediately once a jump's vertical span terminates.
    if (scopeLanesStart_ != sStart || scopeLanesEnd_ != sEnd || scopeLanes_.empty()) {
        scopeLanesStart_ = sStart;
        scopeLanesEnd_ = sEnd;
        std::vector<const cfg::CfaEdge*> scope;
        scope.reserve(cfg_.edges().size());
        for (const cfg::CfaEdge& e : cfg_.edges()) {
            // External-branch rejection: returns, calls and global/indirect
            // transitions never render as tracks.
            if (e.isReturn()) continue;
            if (e.kind == cfg::EdgeKind::Call || e.isComputed()) continue;
            if (e.toRow < 0) continue; // no resolvable in-list destination
            // Intra-function scoping: both endpoints in the function range.
            if (e.fromAddr < sStart || e.fromAddr > sEnd) continue;
            if (e.toAddr < sStart || e.toAddr > sEnd) continue;
            scope.push_back(&e);
        }
        const std::vector<int> lanes = cfg::assignTracks(scope);
        scopeLanes_.clear();
        for (size_t k = 0; k < scope.size(); ++k)
            scopeLanes_[scope[k]] = lanes[k];
    }

    // 2b) Destination-in-window eligibility: draw any jump whose LANDING ROW
    // is comfortably inside the viewport, span-priority colored per window.
    // Long jumps that merely cross the window without landing (destination
    // off-screen) never draw - that is the spaghetti killer. Inbound jumps
    // from functions above render as arrows clipped at the window top, so no
    // visible landing is ever left without its arrow. Landing rows keep a
    // one-row buffer from each viewport edge so arrowhead triangles are never
    // half-clipped by the window boundary (random chopped heads while
    // scrolling).
    std::vector<const cfg::CfaEdge*> subset;
    subset.reserve(cfg_.edges().size());
    for (const cfg::CfaEdge& e : cfg_.edges()) {
        // External-branch rejection: returns, calls and global/indirect
        // transitions never render as tracks.
        if (e.isReturn()) continue;
        if (e.kind == cfg::EdgeKind::Call || e.isComputed()) continue;
        if (e.toRow < 0) continue; // no resolvable in-list destination
        if (e.toRow <= firstRow || e.toRow >= lastRow - 1) continue;
        subset.push_back(&e);
    }

    // 2c) Dynamic track reallocation over the surviving edges only.
    const std::vector<int> lanes = cfg::assignTracks(subset);
    cfaDrawList_.reserve(subset.size());
    for (size_t k = 0; k < subset.size(); ++k)
        cfaDrawList_.push_back({subset[k], lanes[k]});

    cfaDrawValid_ = true;
}

void DisassemblyFieldView::ensureCfaDrawList(int firstRow, int lastRow) {
    if (cfaDrawValid_ && cfaWindowFirst_ == firstRow && cfaWindowLast_ == lastRow)
        return;
    rebuildCfaDrawList(firstRow, lastRow);
}

void DisassemblyFieldView::setCfaMargin(int px) {
    const int clamped = std::clamp(px, kCfaMinMargin, 240);
    if (clamped == cfaMarginPx_) return;
    cfaMarginPx_ = clamped;
    updateScrollBars();
    viewport()->update();
}

const DisassemblyFieldView::DecodedInstruction* DisassemblyFieldView::decodedInstruction(uint64_t addr) {
    auto it = decodedCache_.find(addr);
    if (it != decodedCache_.end())
        return &it->second;

    DecodedInstruction inst;
    inst.address = addr;
    inst.length = model_.instructionLengthAt(addr);
    if (inst.length <= 0) {
        inst.mnemonic.clear();
        inst.operands.clear();
    } else {
        inst.rawBytes = fetchBytesLocal(program_, addr, inst.length);
        if (decomp_ && decomp_->isOpen()) {
            ghidra::AddressFactory* af = program_ ? program_->getAddressFactory() : nullptr;
            if (af) {
                try {
                    std::string text = decomp_->disassembleAt(af->oldGetAddressFromLong(addr), 1);
                    static QRegularExpression instRe(
                        QStringLiteral("^0x([0-9a-fA-F]+):\\s+([A-Za-z][A-Za-z0-9]*)\\s*(.*)$"));
                    QString qtext = QString::fromStdString(text);
                    QString trimmed = qtext.trimmed();
                    auto m = instRe.match(trimmed);
                    if (m.hasMatch()) {
                        bool ok = false;
                        uint64_t parsedAddr = m.captured(1).toULongLong(&ok, 16);
                        if (ok && parsedAddr == addr) {
                            inst.mnemonic = m.captured(2);
                            inst.operands = m.captured(3);
                        }
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[decodedInstruction] exception at 0x" << std::hex
                              << addr << std::dec << ": " << e.what() << std::endl;
                } catch (...) {
                }
            }
        }
        if (inst.mnemonic.isEmpty()) {
            // decode failed — emit raw bytes as a comment
            inst.mnemonic.clear();
            inst.operands = QString("; <failed to decode %1 bytes>")
                               .arg(inst.rawBytes.empty() ? inst.length : static_cast<int>(inst.rawBytes.size()));
        }
    }
    buildTokensForDecoded(inst);
    auto inserted = decodedCache_.insert({addr, std::move(inst)});
    return &inserted.first->second;
}

void DisassemblyFieldView::buildTokensForDecoded(DecodedInstruction& inst) {
    inst.tokens.clear();
    inst.totalCols = 0;

    if (inst.mnemonic.isEmpty() && !inst.operands.startsWith(QLatin1Char(';'))) {
        inst.mnemonic.clear();
        inst.operands.clear();
    }

    if (!inst.mnemonic.isEmpty()) {
        Token addrTok;
        addrTok.text = QStringLiteral("0x%1  ").arg(inst.address, 8, 16, QLatin1Char('0'));
        addrTok.kind = TokenKind::Address;
        addrTok.addr = inst.address;
        addrTok.startCol = inst.totalCols;
        addrTok.len = addrTok.text.size();
        inst.tokens.push_back(addrTok);
        inst.totalCols += addrTok.len;

        if (showBytes_ && !inst.rawBytes.empty()) {
            Token bytesTok;
            bytesTok.text = formatBytes(inst.rawBytes);
            bytesTok.kind = TokenKind::Bytes;
            bytesTok.addr = inst.address;
            bytesTok.startCol = inst.totalCols;
            bytesTok.len = bytesTok.text.size();
            int gap = 30 - bytesTok.len;
            bytesTok.spaceAfter = (gap >= 2) ? gap : 2;
            inst.tokens.push_back(bytesTok);
            inst.totalCols += bytesTok.len + bytesTok.spaceAfter;
        }

        Token mneTok;
        mneTok.text = inst.mnemonic.leftJustified(8, QLatin1Char(' '));
        mneTok.kind = isCallMnemonic(inst.mnemonic) ? TokenKind::Call
                    : isBranchMnemonic(inst.mnemonic) ? TokenKind::Branch
                    : TokenKind::Mnemonic;
        mneTok.addr = inst.address;
        mneTok.startCol = inst.totalCols;
        mneTok.len = mneTok.text.size();
        inst.tokens.push_back(mneTok);
        inst.totalCols += mneTok.len;

        auto opTokens = tokenizeOperands(inst.operands, inst.address);
        for (auto& t : opTokens) {
            t.startCol = inst.totalCols;
            t.len = t.text.size();
            inst.totalCols += t.len + t.spaceAfter;
            inst.tokens.push_back(t);
        }
    } else {
        Token t;
        t.text = inst.operands.isEmpty() ? QStringLiteral(";") : inst.operands;
        t.kind = TokenKind::Comment;
        t.addr = inst.address;
        t.startCol = 0;
        t.len = t.text.size();
        inst.tokens.push_back(t);
        inst.totalCols += t.len;
    }
}

void DisassemblyFieldView::parseFallbackLine(const QString& rawLine, FallbackLine& out) {
    out = FallbackLine{};
    QString trimmed = rawLine.trimmed();
    if (trimmed.isEmpty()) {
        out.comment = QStringLiteral(";");
        return;
    }
    if (isCommentLine(trimmed)) {
        out.comment = trimmed;
        return;
    }
    static QRegularExpression instRe(
        QStringLiteral("^0x([0-9a-fA-F]+):\\s+([A-Za-z][A-Za-z0-9]*)\\s*(.*)$"));
    auto m = instRe.match(trimmed);
    if (m.hasMatch()) {
        bool ok = false;
        out.addr = m.captured(1).toULongLong(&ok, 16);
        out.mne = m.captured(2);
        out.body = m.captured(3);
    } else {
        out.comment = trimmed;
    }
}

void DisassemblyFieldView::buildTokensForFallback(FallbackLine& line) {
    line.tokens.clear();
    line.totalCols = 0;

    if (line.comment.isEmpty() && line.mne.isEmpty()) {
        line.totalCols = 0;
        return;
    }

    if (!line.mne.isEmpty()) {
        Token addrTok;
        addrTok.text = QStringLiteral("0x%1  ").arg(line.addr, 8, 16, QLatin1Char('0'));
        addrTok.kind = TokenKind::Address;
        addrTok.addr = line.addr;
        addrTok.startCol = 0;
        addrTok.len = addrTok.text.size();
        line.tokens.push_back(addrTok);
        line.totalCols += addrTok.len;

        if (showBytes_ && decomp_) {
            int len = 0;
            try {
                len = decomp_->instructionLengthAt(line.addr);
            } catch (...) {
                len = 0;
            }
            if (len > 0) {
                auto bytes = fetchBytesLocal(program_, line.addr, len);
                if (!bytes.empty()) {
                    Token bytesTok;
                    bytesTok.text = formatBytes(bytes);
                    bytesTok.kind = TokenKind::Bytes;
                    bytesTok.addr = line.addr;
                    bytesTok.startCol = line.totalCols;
                    bytesTok.len = bytesTok.text.size();
                    int gap = 30 - bytesTok.len;
                    bytesTok.spaceAfter = (gap >= 2) ? gap : 2;
                    line.tokens.push_back(bytesTok);
                    line.totalCols += bytesTok.len + bytesTok.spaceAfter;
                }
            }
        }

        Token mneTok;
        mneTok.text = line.mne.leftJustified(8, QLatin1Char(' '));
        mneTok.kind = isCallMnemonic(line.mne) ? TokenKind::Call
                    : isBranchMnemonic(line.mne) ? TokenKind::Branch
                    : TokenKind::Mnemonic;
        mneTok.addr = line.addr;
        mneTok.startCol = line.totalCols;
        mneTok.len = mneTok.text.size();
        line.tokens.push_back(mneTok);
        line.totalCols += mneTok.len;

        auto opTokens = tokenizeOperands(line.body, line.addr);
        for (auto& t : opTokens) {
            t.startCol = line.totalCols;
            t.len = t.text.size();
            line.totalCols += t.len + t.spaceAfter;
            line.tokens.push_back(t);
        }
    } else {
        Token t;
        t.text = line.comment;
        t.kind = TokenKind::Comment;
        t.addr = line.addr;
        t.startCol = 0;
        t.len = t.text.size();
        line.tokens.push_back(t);
        line.totalCols += t.len;
    }
}

QString DisassemblyFieldView::lineText(int row) const {
    if (indexBuilt_) {
        const DisasmRow* r = model_.rowAt(row);
        if (!r) return QString();
        if (r->kind == DisasmRow::Kind::Instruction) {
            auto it = decodedCache_.find(r->address);
            if (it != decodedCache_.end()) {
                const DecodedInstruction& inst = it->second;
                QString out;
                for (const Token& t : inst.tokens) {
                    out += t.text;
                    out += QString(t.spaceAfter, QLatin1Char(' '));
                }
                return out;
            }
        }
        if (r->kind == DisasmRow::Kind::FunctionHeader)
            return QString("; === %1 ===").arg(r->text);
        if (r->kind == DisasmRow::Kind::GapComment)
            return r->text;
        return QString();
    }
    if (row < 0 || row >= static_cast<int>(fallbackLines_.size())) return QString();
    const FallbackLine& fl = fallbackLines_[row];
    QString out;
    for (const Token& t : fl.tokens) {
        out += t.text;
        out += QString(t.spaceAfter, QLatin1Char(' '));
    }
    return out;
}

const std::vector<Token>* DisassemblyFieldView::rowTokens(int row) const {
    if (indexBuilt_) {
        const DisasmRow* r = model_.rowAt(row);
        if (!r) return nullptr;
        if (r->kind == DisasmRow::Kind::Instruction) {
            auto it = decodedCache_.find(r->address);
            if (it == decodedCache_.end()) return nullptr;
            return &it->second.tokens;
        }
        scratchTokens_.clear();
        Token t;
        t.text = (r->kind == DisasmRow::Kind::FunctionHeader)
            ? QString("; === %1 ===").arg(r->text)
            : r->text;
        t.kind = TokenKind::Comment;
        t.addr = 0;
        t.startCol = 0;
        t.len = t.text.size();
        scratchTokens_.push_back(t);
        return &scratchTokens_;
    }
    if (row < 0 || row >= static_cast<int>(fallbackLines_.size())) return nullptr;
    return &fallbackLines_[row].tokens;
}

DisassemblyFieldView::CursorPos DisassemblyFieldView::caretAtPos(const QPoint& pos) const {
    int n = lineCount();
    if (n == 0) return {0, 0};
    int cellW = EditorTheme::cellWidth();
    int cellH = EditorTheme::cellHeight();
    int scrollY = verticalScrollBar()->value();
    int scrollX = horizontalScrollBar()->value();
    int row = (pos.y() + scrollY) / cellH;
    row = std::clamp(row, 0, n - 1);
    int col = (pos.x() + scrollX - cfaMarginPx_ - EditorTheme::leftPadding()) / cellW;
    col = std::clamp(col, 0, static_cast<int>(lineText(row).size()));
    return {row, col};
}

const Token* DisassemblyFieldView::tokenAt(int row, int col) const {
    if (row < 0 || row >= lineCount()) return nullptr;
    const std::vector<Token>* toks = rowTokens(row);
    if (!toks) return nullptr;
    for (const Token& t : *toks) {
        if (col >= t.startCol && col < t.startCol + t.len)
            return &t;
    }
    return nullptr;
}

int DisassemblyFieldView::tokenIndexAt(int row, int col) const {
    if (row < 0 || row >= lineCount()) return -1;
    const std::vector<Token>* toks = rowTokens(row);
    if (!toks) return -1;
    for (int i = 0; i < static_cast<int>(toks->size()); ++i) {
        if (col >= (*toks)[i].startCol && col < (*toks)[i].startCol + (*toks)[i].len)
            return i;
    }
    return -1;
}

void DisassemblyFieldView::selectTokenAt(int row, int col) {
    if (row < 0 || row >= lineCount()) return;

    uint64_t lineAddr = 0;
    int length = 0;
    if (indexBuilt_) {
        const DisasmRow* r = model_.rowAt(row);
        if (!r) return;
        if (r->kind != DisasmRow::Kind::Instruction) return; // headers/gaps: no token selection
        lineAddr = r->address;
        length = r->length;
    } else {
        lineAddr = fallbackLines_[row].addr;
    }

    const Token* tok = tokenAt(row, col);
    if (!tok) {
        anchor_ = caret_ = {row, col};
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        currentRow_ = row;
        currentAddr_ = lineAddr;
        if (lineAddr != 0) {
            SelectionState sel;
            sel.valid = true;
            sel.address = lineAddr;
            sel.endAddress = (length > 0) ? lineAddr + length : 0;
            sel.originView = this;
            if (selectionMgr_)
                selectionMgr_->select(sel, this);
            emit cursorAddressChanged(lineAddr);
        }
        return;
    }

    selectedToken_ = {row, tok->startCol, tok->len};
    anchor_ = {row, tok->startCol};
    caret_ = {row, tok->startCol + tok->len};
    highlightWord_ = tok->text;
    highlightKind_ = tok->kind;
    currentRow_ = row;
    currentAddr_ = lineAddr;

    if (lineAddr != 0) {
        SelectionState sel;
        sel.valid = true;
        sel.address = lineAddr;
        sel.endAddress = (length > 0) ? lineAddr + length : 0;
        sel.tokenText = tok->text;
        sel.tokenKind = tok->kind;
        sel.originView = this;
        if (selectionMgr_)
            selectionMgr_->select(sel, this);
        emit cursorAddressChanged(lineAddr);
    }
    viewport()->update();
}

void DisassemblyFieldView::updateScrollBars() {
    int cellW = EditorTheme::cellWidth();
    int cellH = EditorTheme::cellHeight();
    int leftPad = cfaMarginPx_ + EditorTheme::leftPadding();
    int n = lineCount();
    if (n == 0) {
        verticalScrollBar()->setRange(0, 0);
        horizontalScrollBar()->setRange(0, 0);
        return;
    }
    int vpH = viewport()->height();
    int vpW = viewport()->width();
    int vMax = std::max(0, n * cellH - vpH);
    verticalScrollBar()->setRange(0, vMax);
    verticalScrollBar()->setPageStep(vpH);
    verticalScrollBar()->setSingleStep(cellH);

    int contentW = vpW - 2 * leftPad;
    int hMax = std::max(0, maxContentCols() * cellW + 2 * leftPad - vpW);
    horizontalScrollBar()->setRange(0, hMax);
    horizontalScrollBar()->setPageStep(std::max(1, contentW));
    horizontalScrollBar()->setSingleStep(cellW * 4);
}

void DisassemblyFieldView::ensureVisible(int row) {
    int cellH = EditorTheme::cellHeight();
    int y = row * cellH;
    int scrollY = verticalScrollBar()->value();
    int vpH = viewport()->height();
    if (y < scrollY)
        verticalScrollBar()->setValue(std::max(0, y));
    else if (y + cellH > scrollY + vpH)
        verticalScrollBar()->setValue(std::max(0, y + cellH - vpH));
}

void DisassemblyFieldView::paintEvent(QPaintEvent* event) {
    QPainter painter(viewport());
    painter.setRenderHint(QPainter::Antialiasing); // crisp lines + arrowheads

    // Bounding-box safety margin: the exposed-region clip must never slice the
    // outer edge of a thick line or arrowhead that straddles an update
    // boundary. If this frame's update region left any part of the CFG margin
    // strip (padded by kCfaSafetyPad) out, schedule it so partial updates
    // converge to full ink on the next paint pass.
    const QRect marginStrip(0, 0, cfaMarginPx_ + kCfaSafetyPad,
                            viewport()->height());
    if (!marginStrip.intersected(event->rect()).contains(marginStrip))
        viewport()->update(marginStrip);

    painter.fillRect(event->rect(), EditorTheme::backgroundColor());

    int n = lineCount();
    if (n == 0) {
        // placeholder
        painter.setPen(QColor(0x88, 0x88, 0x88));
        painter.drawText(cfaMarginPx_ + EditorTheme::leftPadding(), EditorTheme::ascent() + 4,
                         QStringLiteral("No disassembly"));
        return;
    }

    int cellW = EditorTheme::cellWidth();
    int cellH = EditorTheme::cellHeight();
    int ascent = EditorTheme::ascent();
    int glyphH = EditorTheme::glyphHeight();
    int leftPad = cfaMarginPx_ + EditorTheme::leftPadding();
    int scrollY = verticalScrollBar()->value();
    int scrollX = horizontalScrollBar()->value();
    int vpH = viewport()->height();
    int vpW = viewport()->width();

    int first = scrollY / cellH;
    int last = std::min((scrollY + vpH) / cellH + 1, n - 1);
    int maxSeenBefore = maxColsSeen_;

    // Extremely faint 1px vertical separator isolating the CFG margin from
    // the text area. Drawn BEFORE the CFG gutter so arrowhead tips always
    // paint their apex over it - the old order sliced every head that landed
    // at the margin boundary (random chopped tips).
    painter.fillRect(cfaMarginPx_, 0, 1, vpH, QColor(0xdc, 0xe1, 0xe8));

    if (cfgValid_) {
        paintBlockBackdrop(painter, first, last, cellH, scrollY, vpW);
        ensureCfaDrawList(first, last);
        paintCfaGutter(painter, first, last, cellH, scrollY);
    }

    const QColor* colorTbl = EditorTheme::colorTable();
    const QFont* fontTbl = EditorTheme::fontTable();
    bool hasHighlight = !highlightWord_.isEmpty();

    auto lineSelection = [&](int ri, int& sCol, int& eCol) -> bool {
        if (anchor_ == caret_) return false;
        int r1 = anchor_.row, r2 = caret_.row;
        int c1 = anchor_.col, c2 = caret_.col;
        if (r1 > r2 || (r1 == r2 && c1 > c2)) { std::swap(r1, r2); std::swap(c1, c2); }
        if (ri < r1 || ri > r2) return false;
        if (r1 == r2) { sCol = c1; eCol = c2; }
        else if (ri == r1) { sCol = c1; eCol = static_cast<int>(lineText(r1).size()); }
        else if (ri == r2) { sCol = 0;  eCol = c2; }
        else { sCol = 0; eCol = static_cast<int>(lineText(ri).size()); }
        return true;
    };

    std::unordered_set<uint64_t> patchedSites;
    if (patchMgr_) {
        for (auto* p : patchMgr_->getActivePatches())
            patchedSites.insert(p->baseAddress());
    }

    for (int ri = first; ri <= last; ++ri) {
        int y = ri * cellH - scrollY;
        int baseX = leftPad - scrollX;

        if (ri == currentRow_) {
            painter.fillRect(cfaMarginPx_, y, vpW - cfaMarginPx_, cellH, EditorTheme::caretLineColor());
        }

        const std::vector<Token>* toks = nullptr;
        int maxCol = 0;
        uint64_t rowAddr = 0;
        if (indexBuilt_) {
            const DisasmRow* r = model_.rowAt(ri);
            if (!r) continue;
            rowAddr = r->address;
            if (r->kind == DisasmRow::Kind::Instruction) {
                const DecodedInstruction* inst = decodedInstruction(r->address);
                if (!inst) continue;
                toks = &inst->tokens;
                maxCol = inst->totalCols;
            } else {
                toks = rowTokens(ri);
                maxCol = 0;
                if (toks) {
                    for (const Token& t : *toks)
                        maxCol = std::max(maxCol, t.startCol + t.len);
                }
            }
        } else {
            if (ri >= static_cast<int>(fallbackLines_.size())) continue;
            toks = &fallbackLines_[ri].tokens;
            maxCol = fallbackLines_[ri].totalCols;
            rowAddr = fallbackLines_[ri].addr;
        }
        if (!toks || toks->empty()) continue;

        if (!patchedSites.empty() && rowAddr != 0 && patchedSites.count(rowAddr)) {
            // Patch marker sits at the margin/text boundary, keeping the CFG
            // margin dedicated to arrow graphics.
            painter.fillRect(cfaMarginPx_ + 2, y + 2, 4, cellH - 4, QColor(0x2e, 0xcc, 0x71));
        }

        maxColsSeen_ = std::max(maxColsSeen_, maxCol);

        int selS = 0, selE = 0;
        bool hasSel = lineSelection(ri, selS, selE);
        bool selectedTokenOnLine = (selectedToken_.row == ri && selectedToken_.len > 0);
        if (hasSel && !selectedTokenOnLine) {
            int sx = baseX + selS * cellW;
            int sw = (selE - selS) * cellW;
            painter.fillRect(sx, y, sw, cellH, EditorTheme::selectionColor());
        }

        if (selectedTokenOnLine) {
            int sx = baseX + selectedToken_.startCol * cellW;
            int sw = selectedToken_.len * cellW;
            painter.fillRect(sx, y, sw, cellH, EditorTheme::primarySelectionColor());
        }

        for (const Token& tok : *toks) {
            int ki = static_cast<int>(tok.kind);
            painter.setPen(colorTbl[ki]);
            painter.setFont(fontTbl[ki]);

            bool isSelectedToken = selectedTokenOnLine &&
                tok.startCol == selectedToken_.startCol &&
                tok.len == selectedToken_.len;

            int tx = baseX + tok.startCol * cellW;
            int ty = y + ascent;

            if (hasHighlight && !isSelectedToken &&
                tok.kind == highlightKind_ && tok.text == highlightWord_) {
                painter.fillRect(tx, y, tok.len * cellW, cellH, EditorTheme::occurrenceColor());
            }

            if (isSelectedToken)
                painter.setPen(Qt::white);
            painter.drawText(tx, ty, tok.text);
            if (isSelectedToken)
                painter.setPen(colorTbl[ki]);
        }
    }

    if (hasFocus() && caretVisible_) {
        int cx = leftPad - scrollX + caret_.col * cellW;
        int cy = caret_.row * cellH - scrollY;
        painter.fillRect(cx, cy, 2, glyphH, EditorTheme::textColor());
    }

    if (maxColsSeen_ > maxSeenBefore)
        updateScrollBars();
}

void DisassemblyFieldView::paintBlockBackdrop(QPainter& painter, int first, int last,
                                              int cellH, int scrollY, int vpW) {
    int prevBlock = -2;
    for (int ri = first; ri <= last; ++ri) {
        const cfg::CfgBlock* blk = cfg_.blockAtRow(ri);
        if (!blk) {
            prevBlock = -2;
            continue;
        }
        const int y = ri * cellH - scrollY;
        if (blk->index != prevBlock) {
            // Tints and separators are strictly constrained to the text area:
            // the CFG margin keeps a pure, untouched background.
            painter.fillRect(cfaMarginPx_, y, vpW - cfaMarginPx_, cellH,
                             EditorTheme::blockTint(blk->index));
            painter.setPen(EditorTheme::blockSeparatorColor());
            painter.drawLine(cfaMarginPx_, y, vpW, y);
            prevBlock = blk->index;
        }
    }
}

void DisassemblyFieldView::paintCfaGutter(QPainter& painter, int first, int last,
                                          int cellH, int scrollY) {
    const int x0 = cfaMarginPx_; // text boundary: exits start and tips land here
    const uint64_t sStart = cfaScopeStart_, sEnd = cfaScopeEnd_;

    // Pass A: scoped source stubs for returns and unresolved (computed) exits.
    // Calls and computed calls are fully rejected from the margin; returns get
    // a local stop tab and unresolved in-function jumps a short "?" stub - none
    // of these ever draw a tracker line, so they add no spaghetti.
    for (const cfg::CfaEdge& e : cfg_.edges()) {
        if (e.kind == cfg::EdgeKind::Call || e.isComputed()) continue;
        if (!e.isReturn() && e.toRow >= 0) continue; // real track handled in Pass B
        if (e.fromRow < first || e.fromRow > last) continue;
        if (e.fromAddr < sStart || e.fromAddr > sEnd) continue; // intra-function scope
        QColor color = Qt::black; // crisp classic black for all gutter graphics
        const int y = e.fromRow * cellH - scrollY;
        const int ym = y + cellH / 2;
        if (e.isReturn()) {
            const int stubL = x0 - kCfaStopW * 2;
            painter.setPen(QPen(color, kCfaLineWidth, Qt::SolidLine, Qt::FlatCap,
                                Qt::MiterJoin));
            painter.drawLine(stubL, ym, x0, ym); // short stub from the text edge
            painter.setPen(Qt::NoPen);
            painter.setBrush(color);
            // Stop tab: a clean solid black square at the end of the stub.
            painter.drawRect(QRect(stubL - kCfaStopW, ym - (kCfaStopW - 1),
                                   kCfaStopW * 2, kCfaStopW * 2 - 2));
        } else {
            // Unresolved (computed) target: dashed stub + "?" indicator.
            QPen dash(Qt::DashLine);
            dash.setColor(color);
            dash.setWidth(kCfaLineWidth);
            dash.setCapStyle(Qt::FlatCap);
            dash.setJoinStyle(Qt::MiterJoin);
            painter.setPen(dash);
            painter.drawLine(x0 - 8, ym, x0, ym);
            QFont qf = painter.font();
            qf.setBold(true);
            painter.setFont(qf);
            painter.setPen(color);
            painter.drawText(x0 + 2, y + EditorTheme::ascent(), QStringLiteral("?"));
        }
    }

    // Pass B: tracks from the scope+cull+track drawer list. paintEvent (and
    // edgeAt) rebuild this list for the visible function + viewport window, so
    // only live, on-screen, intra-function jumps are drawn - no overlap, no
    // off-screen lines.
    for (const CfaDrawItem& item : cfaDrawList_) {
        const cfg::CfaEdge& e = *item.edge;
        const bool sel = (item.edge == selectedEdge_);
        // Routing: solid deep black; only the active selection stays a distinct
        // color, so the highlighted jump pops against the black grid.
        QColor color = sel ? QColor(0x00, 0xff, 0x9f) : Qt::black;
        const int w = kCfaLineWidth + (sel ? kCfaSelBoost : 0);

        // Strict orthogonal Ghidra-style route: horizontal exit from the source
        // row out to the nesting column, vertical traversal, horizontal entry
        // back into the target row. Corners meet with sharp miter joints.
        const std::vector<QPoint> route = cfaRoute(e, item.lane, cellH, scrollY);
        QPainterPath path(route[0]);
        for (size_t i = 1; i < route.size(); ++i)
            path.lineTo(route[i]);
        const bool dashed = e.kind == cfg::EdgeKind::Conditional && !sel;
        QPen pen(color, w, dashed ? Qt::DashLine : Qt::SolidLine, Qt::FlatCap,
                 Qt::MiterJoin);
        pen.setCosmetic(true);
        painter.setPen(pen);
        painter.setBrush(Qt::NoBrush);
        if (dashed) {
            // Conditional routing: only the horizontal exit + vertical
            // traversal are dashed. The final horizontal entry approach is
            // SOLID so the arrowhead always connects flush to the line - no
            // detached, floating tip left behind by a dash gap.
            QPainterPath trunk(route[0]);
            trunk.lineTo(route[1]);
            trunk.lineTo(route[2]);
            painter.drawPath(trunk);
            QPen solid(color, w, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin);
            solid.setCosmetic(true);
            painter.setPen(solid);
        }
        painter.drawPath(path);

        // Sharp filled arrowhead: isosceles triangle whose apex sits exactly at
        // the end of the horizontal entry segment (route.back()), base square
        // behind it along the entry - clean, aligned, zero overlap with the
        // line body it caps. All vertices are integer pixels (headW is even),
        // so the polygon never renders sub-pixel or partially hidden.
        const QPoint& tip = route.back();
        QPolygon head;
        head << QPoint(tip.x() - kCfaHeadLen, tip.y() - kCfaHeadW / 2)
             << QPoint(tip.x() - kCfaHeadLen, tip.y() + kCfaHeadW / 2)
             << QPoint(tip);
        painter.setPen(Qt::NoPen);
        painter.setBrush(color);
        painter.drawPolygon(head);
    }
}

std::vector<QPoint> DisassemblyFieldView::cfaRoute(const cfg::CfaEdge& e, int lane,
                                                   int cellH, int scrollY) const {
    const int x0 = cfaMarginPx_; // text boundary
    const int xT = laneX(lane); // nesting column: deeper nesting sits further left
    // Integer pixel alignment: every coordinate is snapped to a clean integer
    // (qRound) so lines land exactly on pixel centers - no sub-pixel blur, no
    // 1px clipping artifacts.
    const int yFrom = qRound(e.fromRow * cellH - scrollY + cellH / 2.0);
    const int yTo = qRound(e.toRow * cellH - scrollY + cellH / 2.0);
    // Strict 90-degree orthogonal routing: horizontal exit, vertical traversal,
    // horizontal entry. Only horizontal and vertical segments - sharp miter
    // joints at the corners, no chamfers, curves or smoothing.
    return {{x0, yFrom}, {xT, yFrom}, {xT, yTo}, {x0, yTo}};
}

const cfg::CfaEdge* DisassemblyFieldView::edgeAt(const QPoint& pos) {
    if (!cfgValid_ || pos.x() >= cfaMarginPx_) return nullptr;
    const int cellH = EditorTheme::cellHeight();
    const int scrollY = verticalScrollBar()->value();
    const int first = scrollY / cellH;
    const int last = std::min((scrollY + viewport()->height()) / cellH + 1,
                              lineCount() - 1);
    // Rebuild the drawer list for the current window so the hit-test only
    // sees the same filtered, in-function, on-screen edges that are drawn.
    ensureCfaDrawList(first, last);
    // Wide-stroke tolerant hit test: a path stroked by ~8px wraps the drawn
    // line, so users needn't click exactly on a hairline route. Tolerance is
    // generous but still only reaches into the CFG margin.
    const cfg::CfaEdge* best = nullptr;
    double bestDist = std::numeric_limits<double>::max();
    QPainterPathStroker stroker;
    stroker.setWidth(8.0);
    stroker.setJoinStyle(Qt::RoundJoin);
    stroker.setCapStyle(Qt::RoundCap);
    for (const CfaDrawItem& it : cfaDrawList_) {
        const std::vector<QPoint> route = cfaRoute(*it.edge, it.lane, cellH, scrollY);
        QPainterPath path(route[0]);
        for (size_t i = 1; i < route.size(); ++i)
            path.lineTo(route[i]);
        if (!stroker.createStroke(path).contains(pos)) continue;
        // Prefer whatever the stroker matched closest to the actual line.
        double d = std::numeric_limits<double>::max();
        for (size_t i = 1; i < route.size(); ++i)
            d = std::min(d, pointSegDist(pos, route[i - 1], route[i]));
        if (d < bestDist - 1e-9) {
            bestDist = d;
            best = it.edge;
        }
    }
    return best;
}

void DisassemblyFieldView::selectEdge(const cfg::CfaEdge* e) {
    if (selectedEdge_ == e) return;
    selectedEdge_ = e;
    viewport()->update();
}

void DisassemblyFieldView::animateScrollToRow(int row, uint64_t destAddr) {
    if (!verticalScrollBar()) return;
    const int cellH = EditorTheme::cellHeight();
    const int vpH = viewport()->height();
    const int current = verticalScrollBar()->value();
    const int maxV = verticalScrollBar()->maximum();
    const int target = std::clamp(row * cellH - (vpH - cellH) / 2, 0, maxV);
    if (scrollAnim_) {
        disconnect(scrollAnim_, nullptr, this, nullptr);
        scrollAnim_->stop();
        scrollAnim_->deleteLater();
        scrollAnim_ = nullptr;
    }
    if (current == target) {
        finishNavTo(row, destAddr);
        return;
    }
    QPropertyAnimation* anim = new QPropertyAnimation(verticalScrollBar(), "value", this);
    anim->setDuration(260);
    anim->setStartValue(current);
    anim->setEndValue(target);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    scrollAnim_ = anim;
    connect(anim, &QPropertyAnimation::finished, this,
            [this, row, destAddr, anim]() {
        if (scrollAnim_ != anim) return; // superseded by a newer slide
        scrollAnim_ = nullptr;
        finishNavTo(row, destAddr);
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void DisassemblyFieldView::finishNavTo(int row, uint64_t destAddr) {
    currentRow_ = row;
    if (destAddr != 0) currentAddr_ = destAddr;
    viewport()->update();
    emit cursorAddressChanged(destAddr);
}

void DisassemblyFieldView::jumpToAddress(uint64_t target) {
    if (target == 0) return;
    seek(target);
    emit seekRequested(target);
    SelectionState sel;
    sel.valid = true;
    sel.address = target;
    sel.endAddress = target + 1;
    sel.tokenText = QStringLiteral("0x%1").arg(target, 0, 16);
    sel.tokenKind = TokenKind::Address;
    sel.originView = this;
    if (selectionMgr_)
        selectionMgr_->select(sel, this);
}

void DisassemblyFieldView::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    updateScrollBars();
}

void DisassemblyFieldView::wheelEvent(QWheelEvent* event) {
    QAbstractScrollArea::wheelEvent(event);
}

void DisassemblyFieldView::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        if (lineCount() == 0) return;
        viewport()->setFocus();
        resetCaretBlink();
        if (event->pos().x() < cfaMarginPx_) {
            // Single click in the gutter highlights the edge (neon) but does
            // not navigate - smooth traversal is performed on double-click.
            selectEdge(edgeAt(event->pos()));
            return;
        }
        auto hit = caretAtPos(event->pos());
        anchor_ = caret_ = {hit.row, hit.col};
        selecting_ = true;
        dragging_ = false;
        currentRow_ = hit.row;
        currentAddr_ = (indexBuilt_ ? model_.rowToAddress(hit.row) : fallbackLines_[hit.row].addr);
        viewport()->update();
        return;
    }
    QAbstractScrollArea::mousePressEvent(event);
}

void DisassemblyFieldView::mouseMoveEvent(QMouseEvent* event) {
    if (selecting_) {
        auto hit = caretAtPos(event->pos());
        if (hit.row != caret_.row || hit.col != caret_.col) {
            dragging_ = true;
            selectedToken_ = {};
            highlightWord_.clear();
            highlightKind_ = TokenKind::Plain;
        }
        caret_ = {hit.row, hit.col};
        viewport()->update();
        return;
    }
    auto hit = caretAtPos(event->pos());
    const Token* tok = tokenAt(hit.row, hit.col);
    if (event->pos().x() < cfaMarginPx_) {
        if (const cfg::CfaEdge* e = edgeAt(event->pos())) {
            viewport()->setCursor(Qt::PointingHandCursor);
            const QString label = QStringLiteral("%1: 0x%2 -> 0x%3")
                .arg(QLatin1String(cfg::edgeKindName(e->kind)))
                .arg(e->fromAddr, 0, 16)
                .arg(e->toAddr, 0, 16);
            if (viewport()->toolTip() != label)
                viewport()->setToolTip(label);
            QAbstractScrollArea::mouseMoveEvent(event);
            return;
        }
        viewport()->setToolTip(QString());
    }
    bool clickable = tok && (tok->refTarget != 0 ||
        tok->kind == TokenKind::Function ||
        tok->kind == TokenKind::Label ||
        tok->kind == TokenKind::Address);
    viewport()->setCursor(clickable ? Qt::PointingHandCursor : Qt::ArrowCursor);
    QAbstractScrollArea::mouseMoveEvent(event);
}

void DisassemblyFieldView::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton && selecting_) {
        if (lineCount() == 0) { selecting_ = false; return; }
        selecting_ = false;
        if (!dragging_) {
            auto hit = caretAtPos(event->pos());
            caret_ = {hit.row, hit.col};
            const Token* tok = tokenAt(hit.row, hit.col);
            if (tok) {
                if (event->modifiers() & Qt::ControlModifier) {
                    uint64_t target = tok->refTarget
                        ? tok->refTarget
                        : (tok->kind == TokenKind::Address ? tok->addr : 0);
                    if (target != 0) {
                        seek(target);
                        emit seekRequested(target);
                        dragging_ = false;
                        return;
                    }
                }
            }
            selectTokenAt(hit.row, hit.col);
        } else {
            selectedToken_ = {};
            highlightWord_.clear();
            highlightKind_ = TokenKind::Plain;
            uint64_t addr = (indexBuilt_ ? model_.rowToAddress(caret_.row) : fallbackLines_[caret_.row].addr);
            if (addr != 0)
                emit cursorAddressChanged(addr);
        }
        dragging_ = false;
        viewport()->update();
        return;
    }
    QAbstractScrollArea::mouseReleaseEvent(event);
}

void DisassemblyFieldView::mouseDoubleClickEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        if (lineCount() == 0) return;
        // Gutter: single highlight already set on press; double-click animates a
        // smooth scroll that centers the destination (no instant re-seek).
        if (event->pos().x() < cfaMarginPx_ && cfgValid_) {
            const cfg::CfaEdge* e = edgeAt(event->pos());
            selectEdge(e);
            if (e && e->resolved() && e->toRow >= 0 && e->fromRow >= 0 && e->toAddr != 0) {
                SelectionState sel;
                sel.valid = true;
                sel.address = e->toAddr;
                sel.endAddress = e->toAddr + 1;
                sel.tokenText = QStringLiteral("0x%1").arg(e->toAddr, 0, 16);
                sel.tokenKind = TokenKind::Address;
                sel.originView = this;
                if (selectionMgr_)
                    selectionMgr_->select(sel, this);
                animateScrollToRow(e->toRow, e->toAddr);
                return;
            }
            return;
        }
        selecting_ = false;
        dragging_ = false;
        auto hit = caretAtPos(event->pos());
        const Token* tok = tokenAt(hit.row, hit.col);
        if (tok) {
            uint64_t target = tok->refTarget
                ? tok->refTarget
                : (tok->kind == TokenKind::Address ? tok->addr : 0);
            if (target != 0) {
                seek(target);
                emit seekRequested(target);
                SelectionState sel;
                sel.valid = true;
                sel.address = target;
                sel.endAddress = target + 1;
                sel.tokenText = QString("0x%1").arg(target, 0, 16);
                sel.tokenKind = TokenKind::Address;
                sel.originView = this;
                if (selectionMgr_)
                    selectionMgr_->select(sel, this);
                return;
            }
            selectedToken_ = {hit.row, tok->startCol, tok->len};
            anchor_ = {hit.row, tok->startCol};
            caret_ = {hit.row, tok->startCol + tok->len};
            highlightWord_ = tok->text;
            highlightKind_ = tok->kind;
            currentRow_ = hit.row;
            currentAddr_ = (indexBuilt_ ? model_.rowToAddress(hit.row) : fallbackLines_[hit.row].addr);
            if (currentAddr_ != 0) {
                SelectionState sel;
                sel.valid = true;
                sel.address = currentAddr_;
                sel.endAddress = 0;
                sel.tokenText = tok->text;
                sel.tokenKind = tok->kind;
                sel.originView = this;
                if (selectionMgr_)
                    selectionMgr_->select(sel, this);
                emit cursorAddressChanged(currentAddr_);
            }
            viewport()->update();
            return;
        }
    }
    QAbstractScrollArea::mouseDoubleClickEvent(event);
}

void DisassemblyFieldView::contextMenuEvent(QContextMenuEvent* event) {
    QMenu menu(this);
    QAction* actExport = menu.addAction(tr("Export Patched Binary..."));
    QAction* actAssemble = nullptr;
    QAction* actGoTo = nullptr;
    QAction* actJumpToCave = nullptr;
    uint64_t caveTarget = 0;

    auto hit = caretAtPos(event->pos());
    bool onInstruction = hit.row >= 0 && hit.row < lineCount();
    uint64_t addr = 0;
    QString mne;
    QString ops;
    if (onInstruction) {
        if (indexBuilt_) {
            const DisasmRow* r = model_.rowAt(hit.row);
            if (!r || r->kind != DisasmRow::Kind::Instruction) onInstruction = false;
            else {
                addr = r->address;
                const DecodedInstruction* inst = decodedInstruction(addr);
                if (inst) {
                    mne = inst->mnemonic;
                    ops = inst->operands;
                }
            }
        } else {
            const FallbackLine& fl = fallbackLines_[hit.row];
            addr = fl.addr;
            mne = fl.mne;
            ops = fl.body;
            if (addr == 0) onInstruction = false;
        }
    }

    if (onInstruction) {
        menu.addSeparator();
        actAssemble = menu.addAction(tr("Assemble Instruction at 0x%1").arg(addr, 0, 16));
        actGoTo = menu.addAction(tr("Go to 0x%1").arg(addr, 0, 16));
        auto caveIt = trampolineMap_.find(addr);
        if (caveIt != trampolineMap_.end()) {
            actJumpToCave = menu.addAction(tr("Jump to Code Cave (0x%1)").arg(caveIt->second, 0, 16));
            caveTarget = caveIt->second;
        }
    }

    QAction* chosen = menu.exec(event->globalPos());
    if (!chosen) return;

    if (chosen == actExport) {
        emit exportPatchedRequested();
    } else if (chosen == actAssemble) {
        emit patchInstructionRequested(addr, mne, ops);
    } else if (chosen == actJumpToCave) {
        emit addressJumpRequested(caveTarget);
    } else if (chosen == actGoTo) {
        seek(addr);
    }
}

void DisassemblyFieldView::keyPressEvent(QKeyEvent* event) {
    resetCaretBlink();
    if (event->matches(QKeySequence::Copy)) {
        copySelection();
        return;
    }
    if (event->matches(QKeySequence::SelectAll)) {
        selectAll();
        return;
    }
    int n = lineCount();
    if (n == 0) {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }
    int oldRow = caret_.row;
    bool shifted = event->modifiers() & Qt::ShiftModifier;
    int rowsPerPage = std::max(1, viewport()->height() / EditorTheme::cellHeight());

    auto moveTo = [&](int newRow, int newCol) {
        newRow = std::clamp(newRow, 0, n - 1);
        newCol = std::clamp(newCol, 0, static_cast<int>(lineText(newRow).size()));
        if (shifted) {
            caret_ = {newRow, newCol};
        } else {
            anchor_ = caret_ = {newRow, newCol};
        }
        currentRow_ = newRow;
        currentAddr_ = (indexBuilt_ ? model_.rowToAddress(newRow) : fallbackLines_[newRow].addr);
        ensureVisible(newRow);
        viewport()->update();
    };

    switch (event->key()) {
    case Qt::Key_Up:       moveTo(caret_.row - 1, caret_.col); break;
    case Qt::Key_Down:     moveTo(caret_.row + 1, caret_.col); break;
    case Qt::Key_PageUp:   moveTo(caret_.row - rowsPerPage, caret_.col); break;
    case Qt::Key_PageDown: moveTo(caret_.row + rowsPerPage, caret_.col); break;
    case Qt::Key_Home:
        if (event->modifiers() & Qt::ControlModifier)
            moveTo(0, 0);
        else
            moveTo(caret_.row, 0);
        break;
    case Qt::Key_End:
        if (event->modifiers() & Qt::ControlModifier)
            moveTo(n - 1, static_cast<int>(lineText(n - 1).size()));
        else
            moveTo(caret_.row, static_cast<int>(lineText(caret_.row).size()));
        break;
    case Qt::Key_Left: {
        int row = caret_.row;
        int col = caret_.col;
        int idx = tokenIndexAt(row, col);
        const std::vector<Token>* toks = rowTokens(row);
        if (idx > 0 && toks) {
            moveTo(row, (*toks)[idx - 1].startCol);
        } else if (idx == 0 || (idx < 0 && col > 0)) {
            moveTo(row, 0);
        } else if (row > 0) {
            moveTo(row - 1, static_cast<int>(lineText(row - 1).size()));
        }
        break;
    }
    case Qt::Key_Right: {
        int row = caret_.row;
        int col = caret_.col;
        int idx = tokenIndexAt(row, col);
        const std::vector<Token>* toks = rowTokens(row);
        if (idx >= 0 && toks && idx + 1 < static_cast<int>(toks->size())) {
            moveTo(row, (*toks)[idx + 1].startCol);
        } else if (row + 1 < n) {
            moveTo(row + 1, 0);
        }
        break;
    }
    default:
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    if (!shifted) {
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        selectTokenAt(caret_.row, caret_.col);
    }

    if (oldRow != caret_.row) {
        uint64_t newAddr = (indexBuilt_ ? model_.rowToAddress(caret_.row) : fallbackLines_[caret_.row].addr);
        if (newAddr != 0)
            emit cursorAddressChanged(newAddr);
    }
}

void DisassemblyFieldView::selectAll() {
    int n = lineCount();
    if (n == 0) return;
    anchor_ = {0, 0};
    caret_ = {n - 1, static_cast<int>(lineText(n - 1).size())};
    viewport()->update();
}

void DisassemblyFieldView::copySelection() {
    if (anchor_ == caret_) return;
    int r1 = anchor_.row, r2 = caret_.row;
    int c1 = anchor_.col, c2 = caret_.col;
    if (r1 > r2 || (r1 == r2 && c1 > c2)) { std::swap(r1, r2); std::swap(c1, c2); }
    QString result;
    for (int i = r1; i <= r2; ++i) {
        const QString line = lineText(i);
        if (i == r1 && i == r2)
            result += line.mid(c1, c2 - c1);
        else if (i == r1)
            result += line.mid(c1);
        else if (i == r2)
            result += line.left(c2);
        else
            result += line;
        if (i < r2) result += QLatin1Char('\n');
    }
    QApplication::clipboard()->setText(result);
}

void DisassemblyFieldView::resetCaretBlink() {
    caretVisible_ = true;
    if (caretBlinkTimer_) {
        caretBlinkTimer_->setInterval(qMax(100, QApplication::cursorFlashTime() / 2));
        caretBlinkTimer_->start();
    }
    viewport()->update();
}

void DisassemblyFieldView::focusInEvent(QFocusEvent* event) {
    QAbstractScrollArea::focusInEvent(event);
    resetCaretBlink();
}

void DisassemblyFieldView::focusOutEvent(QFocusEvent* event) {
    QAbstractScrollArea::focusOutEvent(event);
    caretVisible_ = false;
    viewport()->update();
}

void DisassemblyFieldView::moveCursorTo(int row, int col) {
    int n = lineCount();
    if (n == 0) return;
    row = std::clamp(row, 0, n - 1);
    col = std::clamp(col, 0, static_cast<int>(lineText(row).size()));
    anchor_ = caret_ = {row, col};
    currentRow_ = row;
    currentAddr_ = (indexBuilt_ ? model_.rowToAddress(row) : fallbackLines_[row].addr);
    ensureVisible(row);
    viewport()->update();
}

void DisassemblyFieldView::setSelectionManager(SelectionManager* mgr) {
    if (selectionMgr_ == mgr) return;
    if (selectionMgr_)
        disconnect(selectionMgr_, &SelectionManager::selectionChanged,
                   this, &DisassemblyFieldView::applySelection);
    selectionMgr_ = mgr;
    if (selectionMgr_)
        connect(selectionMgr_, &SelectionManager::selectionChanged,
                this, &DisassemblyFieldView::applySelection);
}

void DisassemblyFieldView::applySelection(const SelectionState& sel) {
    if (sel.originView == this) return;
    currentSelection_ = sel;
    if (!sel.valid || lineCount() == 0) {
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        viewport()->update();
        return;
    }

    bool moved = false;
    int row = -1;
    if (sel.address != 0) {
        if (indexBuilt_) {
            row = model_.addressToRow(sel.address);
            if (row < 0) {
                // fall back to nearest
                int lo = 0, hi = model_.rowCount() - 1, best = -1;
                while (lo <= hi) {
                    int mid = lo + (hi - lo) / 2;
                    const DisasmRow* r = model_.rowAt(mid);
                    if (r && r->address <= sel.address) { best = mid; lo = mid + 1; }
                    else hi = mid - 1;
                }
                while (best >= 0) {
                    const DisasmRow* r = model_.rowAt(best);
                    if (!r) break;
                    if (r->kind == DisasmRow::Kind::Instruction) { row = best; break; }
                    if (r->kind == DisasmRow::Kind::FunctionHeader &&
                        best + 1 < model_.rowCount()) {
                        const DisasmRow* next = model_.rowAt(best + 1);
                        if (next && next->kind == DisasmRow::Kind::Instruction &&
                            next->address <= sel.address) {
                            row = best + 1;
                            break;
                        }
                    }
                    --best;
                }
            }
        } else {
            for (int i = 0; i < static_cast<int>(fallbackLines_.size()); ++i) {
                if (fallbackLines_[i].addr != 0 && fallbackLines_[i].addr <= sel.address)
                    row = i;
                else if (fallbackLines_[i].addr > sel.address)
                    break;
            }
        }
        if (row >= 0) {
            currentRow_ = row;
            currentAddr_ = sel.address;
            moved = true;
        }
    }

    if (!sel.tokenText.isEmpty()) {
        const Token* tok = nullptr;
        if (row >= 0)
            tok = tokenAt(row, 0); // find by matching tokens below
        bool found = false;
        if (row >= 0) {
            if (indexBuilt_) {
                const DisasmRow* r = model_.rowAt(row);
                if (r && r->kind == DisasmRow::Kind::Instruction) {
                    auto it = decodedCache_.find(r->address);
                    if (it != decodedCache_.end()) {
                        for (const Token& t : it->second.tokens) {
                            if (t.text == sel.tokenText &&
                                (sel.tokenKind == TokenKind::Plain || t.kind == sel.tokenKind)) {
                                selectedToken_ = {row, t.startCol, t.len};
                                anchor_ = {row, t.startCol};
                                caret_ = {row, t.startCol + t.len};
                                highlightWord_ = t.text;
                                highlightKind_ = t.kind;
                                found = true;
                                break;
                            }
                        }
                    }
                }
            } else {
                for (const Token& t : fallbackLines_[row].tokens) {
                    if (t.text == sel.tokenText &&
                        (sel.tokenKind == TokenKind::Plain || t.kind == sel.tokenKind)) {
                        selectedToken_ = {row, t.startCol, t.len};
                        anchor_ = {row, t.startCol};
                        caret_ = {row, t.startCol + t.len};
                        highlightWord_ = t.text;
                        highlightKind_ = t.kind;
                        found = true;
                        break;
                    }
                }
            }
        }
        if (!found) {
            selectedToken_ = {};
            highlightWord_ = sel.tokenText;
            highlightKind_ = sel.tokenKind;
        }
    } else {
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        if (row >= 0)
            anchor_ = caret_ = {row, 0};
    }

    if (moved)
        ensureVisible(currentRow_);
    viewport()->update();
}

QString DisassemblyFieldView::formatBytes(const std::vector<uint8_t>& bytes) {
    QString out;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i) out += QLatin1Char(' ');
        out += QStringLiteral("%1").arg(bytes[i], 2, 16, QLatin1Char('0'));
    }
    return out;
}

bool DisassemblyFieldView::isCallMnemonic(const QString& mne) {
    static const QStringList calls = {
        QStringLiteral("CALL"), QStringLiteral("CALLF"),
        QStringLiteral("CALLQ"), QStringLiteral("CALLW"), QStringLiteral("CALLD"),
        QStringLiteral("CALLT")
    };
    return calls.contains(mne.toUpper());
}

bool DisassemblyFieldView::isBranchMnemonic(const QString& mne) {
    static const QStringList branch = {
        QStringLiteral("JMP"), QStringLiteral("JMPF"),
        QStringLiteral("JE"), QStringLiteral("JNE"), QStringLiteral("JZ"), QStringLiteral("JNZ"),
        QStringLiteral("JA"), QStringLiteral("JAE"), QStringLiteral("JB"), QStringLiteral("JBE"),
        QStringLiteral("JG"), QStringLiteral("JGE"), QStringLiteral("JL"), QStringLiteral("JLE"),
        QStringLiteral("JO"), QStringLiteral("JNO"), QStringLiteral("JS"), QStringLiteral("JNS"),
        QStringLiteral("JP"), QStringLiteral("JNP"), QStringLiteral("JC"), QStringLiteral("JNC"),
        QStringLiteral("RET"), QStringLiteral("RETN"), QStringLiteral("RETF"),
        QStringLiteral("IRET"), QStringLiteral("IRETD"), QStringLiteral("IRETQ"),
        QStringLiteral("SYSCALL"), QStringLiteral("SYSRET"), QStringLiteral("SYSENTER"),
        QStringLiteral("INT"), QStringLiteral("INT3"), QStringLiteral("INTO"),
        QStringLiteral("LOOP"), QStringLiteral("LOOPE"), QStringLiteral("LOOPNE"),
        QStringLiteral("LOOPZ"), QStringLiteral("LOOPNZ")
    };
    return branch.contains(mne.toUpper());
}

TokenKind DisassemblyFieldView::classifyIdentifier(const QString& id) const {
    static const QStringList registers = {
        QStringLiteral("eax"), QStringLiteral("ebx"), QStringLiteral("ecx"),
        QStringLiteral("edx"), QStringLiteral("esi"), QStringLiteral("edi"),
        QStringLiteral("ebp"), QStringLiteral("esp"), QStringLiteral("eip"),
        QStringLiteral("rax"), QStringLiteral("rbx"), QStringLiteral("rcx"),
        QStringLiteral("rdx"), QStringLiteral("rsi"), QStringLiteral("rdi"),
        QStringLiteral("rbp"), QStringLiteral("rsp"), QStringLiteral("rip"),
        QStringLiteral("r8"),  QStringLiteral("r9"),  QStringLiteral("r10"),
        QStringLiteral("r11"), QStringLiteral("r12"), QStringLiteral("r13"),
        QStringLiteral("r14"), QStringLiteral("r15"),
        QStringLiteral("r8d"), QStringLiteral("r9d"), QStringLiteral("r10d"),
        QStringLiteral("r11d"),QStringLiteral("r12d"),QStringLiteral("r13d"),
        QStringLiteral("r14d"),QStringLiteral("r15d"),
        QStringLiteral("r8w"), QStringLiteral("r9w"), QStringLiteral("r10w"),
        QStringLiteral("r11w"),QStringLiteral("r12w"),QStringLiteral("r13w"),
        QStringLiteral("r14w"),QStringLiteral("r15w"),
        QStringLiteral("r8b"), QStringLiteral("r9b"), QStringLiteral("r10b"),
        QStringLiteral("r11b"),QStringLiteral("r12b"),QStringLiteral("r13b"),
        QStringLiteral("r14b"),QStringLiteral("r15b"),
        QStringLiteral("ax"),  QStringLiteral("bx"),  QStringLiteral("cx"),
        QStringLiteral("dx"),  QStringLiteral("si"),  QStringLiteral("di"),
        QStringLiteral("bp"),  QStringLiteral("sp"),
        QStringLiteral("ah"),  QStringLiteral("bh"),  QStringLiteral("ch"),
        QStringLiteral("dh"),  QStringLiteral("al"),  QStringLiteral("bl"),
        QStringLiteral("cl"),  QStringLiteral("dl"),
        QStringLiteral("sil"), QStringLiteral("dil"), QStringLiteral("bpl"),
        QStringLiteral("spl"),
        QStringLiteral("xmm0"), QStringLiteral("xmm1"), QStringLiteral("xmm2"),
        QStringLiteral("xmm3"), QStringLiteral("xmm4"), QStringLiteral("xmm5"),
        QStringLiteral("xmm6"), QStringLiteral("xmm7"),
        QStringLiteral("ymm0"), QStringLiteral("ymm1"), QStringLiteral("ymm2"),
        QStringLiteral("ymm3"), QStringLiteral("ymm4"), QStringLiteral("ymm5"),
        QStringLiteral("ymm6"), QStringLiteral("ymm7"),
        QStringLiteral("cs"),  QStringLiteral("ds"),  QStringLiteral("es"),
        QStringLiteral("fs"),  QStringLiteral("gs"),  QStringLiteral("ss"),
        QStringLiteral("st0"), QStringLiteral("st1"), QStringLiteral("st2"),
        QStringLiteral("st3"), QStringLiteral("st4"), QStringLiteral("st5"),
        QStringLiteral("st6"), QStringLiteral("st7"),
    };
    QString lower = id.toLower();
    if (registers.contains(lower))
        return TokenKind::Register;
    bool allDigits = true;
    for (const QChar& c : id) {
        if (!c.isDigit()) { allDigits = false; break; }
    }
    if (allDigits) return TokenKind::Number;
    return TokenKind::Plain;
}

std::vector<Token> DisassemblyFieldView::tokenizeOperands(const QString& ops, uint64_t lineAddr) {
    std::vector<Token> result;
    int n = ops.size();
    int i = 0;
    int bracketDepth = 0;

    auto consumeSpaces = [&](int pos) {
        while (pos < n && ops[pos].isSpace()) ++pos;
        return pos;
    };

    auto addToken = [&](const QString& text, TokenKind kind) {
        if (text.isEmpty()) return;
        Token t;
        t.text = text;
        t.kind = kind;
        t.addr = lineAddr;
        result.push_back(t);
    };

    while (i < n) {
        QChar c = ops[i];
        if (c.isSpace()) {
            ++i;
            continue;
        }

        if (c == QLatin1Char('0') && i + 1 < n && ops[i + 1] == QLatin1Char('x')) {
            int j = i + 2;
            while (j < n && (ops[j].isDigit() ||
                             (ops[j] >= QLatin1Char('a') && ops[j] <= QLatin1Char('f')) ||
                             (ops[j] >= QLatin1Char('A') && ops[j] <= QLatin1Char('F')))) ++j;
            QString txt = ops.mid(i, j - i);
            Token t;
            t.text = txt;
            t.kind = bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Immediate;
            t.addr = lineAddr;
            bool ok = false;
            uint64_t val = txt.mid(2).toULongLong(&ok, 16);
            if (ok && val > 0x1000) t.refTarget = val;
            result.push_back(t);
            i = consumeSpaces(j);
            result.back().spaceAfter = i - j;
            continue;
        }

        if (c.isLetter() || c == QLatin1Char('_')) {
            int j = i;
            while (j < n && (ops[j].isLetterOrNumber() || ops[j] == QLatin1Char('_'))) ++j;
            QString id = ops.mid(i, j - i);
            TokenKind k = classifyIdentifier(id);
            if (bracketDepth > 0 && k != TokenKind::Register) k = TokenKind::MemRef;
            addToken(id, k);
            i = consumeSpaces(j);
            result.back().spaceAfter = i - j;
            continue;
        }

        if (c == QLatin1Char('[')) {
            addToken(QStringLiteral("["), TokenKind::MemRef);
            ++bracketDepth;
            ++i;
            continue;
        }
        if (c == QLatin1Char(']')) {
            addToken(QStringLiteral("]"), TokenKind::MemRef);
            if (bracketDepth > 0) --bracketDepth;
            ++i;
            continue;
        }

        if (c == QLatin1Char('+') || c == QLatin1Char('-') || c == QLatin1Char('*') ||
            c == QLatin1Char(',') || c == QLatin1Char(':') ||
            c == QLatin1Char('(') || c == QLatin1Char(')')) {
            addToken(ops.mid(i, 1), bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Punctuation);
            ++i;
            continue;
        }

        addToken(ops.mid(i, 1), bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Plain);
        ++i;
    }
    return result;
}

bool DisassemblyFieldView::isCommentLine(const QString& trimmed) {
    return trimmed.startsWith(QLatin1Char(';'))
        || trimmed.startsWith(QStringLiteral("//"));
}

std::vector<uint8_t> DisassemblyFieldView::fetchBytesLocal(ghidra::ProgramDB* program, uint64_t addr, int len) {
    if (!program || len <= 0) return {};
    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    if (!mem || !af) return {};
    ghidra::Address a = af->oldGetAddressFromLong(addr);
    std::vector<uint8_t> buf(len);
    try {
        int got = mem->getBytes(a, buf.data(), len);
        if (got > 0) {
            buf.resize(got);
            return buf;
        }
    } catch (...) {}
    return {};
}
