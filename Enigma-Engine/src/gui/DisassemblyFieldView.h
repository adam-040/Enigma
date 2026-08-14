#pragma once

#include <QAbstractScrollArea>
#include <QString>
#include <QTimer>
#include <QRegularExpression>
#include <QStringList>
#include <cstdint>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include "FieldView.h" // Token, TokenKind
#include "DisassemblyModel.h"
#include <cfg/DisassemblyCFG.h>
#include "gui/CutterSeekable.h"
#include "SelectionState.h"

class QPropertyAnimation;
class SelectionManager;

namespace ghidra {
class ProgramDB;
class DecompInterface;
namespace patch { class PatchManager; }
}

class DisassemblyFieldView : public QAbstractScrollArea, public CutterSeekable {
    Q_OBJECT
public:
    explicit DisassemblyFieldView(QWidget* parent = nullptr);
    ~DisassemblyFieldView() override = default;

    void showDisassembly(const QString& text);
    void setProgram(ghidra::ProgramDB* program);
    void setDecompInterface(ghidra::DecompInterface* decomp);
    void setPatchManager(ghidra::patch::PatchManager* patchMgr);
    void setShowBytes(bool show);
    bool showBytes() const { return showBytes_; }

    void buildFullIndex();
    void seekToAddress(uint64_t addr);
    bool isIndexBuilt() const { return indexBuilt_; }
    int totalInstructions() const { return indexBuilt_ ? model_.totalInstructions() : 0; }
    int rowCount() const;
    int lineCount() const;
    int currentRow() const { return currentRow_; }
    void seekToRow(int row);
    void setSearchHighlight(const QString& query, bool matchCase = false, int activeRow = -1);
    void clearSearchHighlight();
    QString lineText(int row) const;
    std::pair<uint64_t, uint64_t> visibleAddressRange() const;
    void setTrampolineMap(std::map<uint64_t, uint64_t> map) { trampolineMap_ = std::move(map); }

    // Invalidate decoded instruction cache (after byte patches)
    void invalidateCache();
    void invalidateRange(uint64_t start, uint64_t end);

    // CutterSeekable
    void seek(uint64_t addr) override;
    uint64_t currentAddress() const override { return currentAddr_; }
    void setSyncState(bool synced) override { synced_ = synced; }
    bool syncState() const override { return synced_; }

    void setSelectionManager(SelectionManager* mgr);
    SelectionManager* selectionManager() const { return selectionMgr_; }
    SelectionState currentSelection() const { return currentSelection_; }

    // Width (px) of the margin dedicated to CFG graphics. Adjustable at
    // runtime; clamped to [kCfaMinMargin, 160]. The disassembly text is
    // always offset past this margin.
    void setCfaMargin(int px);
    int cfaMargin() const { return cfaMarginPx_; }

    // Control-flow graph built over the current index (nullptr when idle).
    const cfg::DisassemblyCFG* cfg() const { return cfgValid_ ? &cfg_ : nullptr; }
    static int laneX(int lane);

signals:
    void seekRequested(uint64_t addr);
    void cursorAddressChanged(uint64_t addr);
    void addressJumpRequested(uint64_t addr);
    void patchInstructionRequested(uint64_t addr, const QString& currentMnemonic,
                                   const QString& currentOperands);
    void showReferencesRequested(uint64_t addr, bool to);
    void exportPatchedRequested();
    void openSearchRequested();

public slots:
    void applySelection(const SelectionState& sel);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void focusInEvent(QFocusEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;

private:
    struct DecodedInstruction {
        uint64_t address = 0;
        int length = 0;
        QString mnemonic;
        QString operands;
        std::vector<uint8_t> rawBytes;
        std::vector<Token> tokens;
        int totalCols = 0;
    };

    struct FallbackLine {
        uint64_t addr = 0;
        QString mne;
        QString body;
        QString comment; // non-empty for comment/blank lines
        std::vector<Token> tokens;
        int totalCols = 0;
    };

    struct CursorPos {
        int row = 0; int col = 0;
        bool operator==(const CursorPos& o) const { return row == o.row && col == o.col; }
        bool operator!=(const CursorPos& o) const { return !(*this == o); }
    };

    struct SelectedToken {
        int row = -1;
        int startCol = -1;
        int len = 0;
        bool contains(int r, int c) const {
            return row == r && c >= startCol && c < startCol + len;
        }
    };

    const DecodedInstruction* decodedInstruction(uint64_t addr);
    void buildTokensForDecoded(DecodedInstruction& inst);
    void buildTokensForFallback(FallbackLine& line);
    void parseFallbackLine(const QString& rawLine, FallbackLine& out);

    std::vector<Token> tokenizeOperands(const QString& ops, uint64_t lineAddr);
    TokenKind classifyIdentifier(const QString& id) const;
    static bool isCallMnemonic(const QString& mne);
    static bool isBranchMnemonic(const QString& mne);
    static QString formatBytes(const std::vector<uint8_t>& bytes);
    static bool isCommentLine(const QString& trimmed);
    static std::vector<uint8_t> fetchBytesLocal(ghidra::ProgramDB* program, uint64_t addr, int len);

    int maxContentCols() const;
    CursorPos caretAtPos(const QPoint& pos) const;
    const Token* tokenAt(int row, int col) const;
    int tokenIndexAt(int row, int col) const;
    void selectTokenAt(int row, int col);
    void updateScrollBars();
    void ensureVisible(int row);
    void selectAll();
    void copySelection();
    void resetCaretBlink();
    void moveCursorTo(int row, int col);
    const std::vector<Token>* rowTokens(int row) const;
    uint64_t addressAtCurrentRow() const;
    void syncCurrentAddress();

    int rows() const;

    DisassemblyModel model_;
    ghidra::ProgramDB* program_ = nullptr;
    ghidra::DecompInterface* decomp_ = nullptr;
    ghidra::patch::PatchManager* patchMgr_ = nullptr;
    bool showBytes_ = false;
    bool indexBuilt_ = false;
    std::map<uint64_t, uint64_t> trampolineMap_; // site → cave

    // --- CFA gutter geometry (screen px) ---
    // Ghidra-style control-flow arrows: each edge is an orthogonal three-
    // segment route - horizontal exit out of the source row, vertical
    // traversal, horizontal entry into the target row - strictly 90 degrees
    // with sharp miter joints, drawn with a 2px pen (solid for unconditional
    // edges, dashed for conditional) and a solid filled triangle arrowhead at
    // the tip. Routing lines and heads are solid deep black; only the active
    // selection uses a distinct color.
    //
    // The left margin (kCfaMarginDefault, runtime-adjustable via setCfaMargin)
    // is a wide, strictly isolated rendering space reserved exclusively for
    // the CFG tracks: block tints, separators and the caret-line highlight
    // are all clamped to start at the margin edge, so the margin keeps a pure
    // background, and a single faint 1px vertical line (painted in paintEvent)
    // separates the margin from the text area. The disassembly text always
    // starts past the margin plus the normal text padding.
    //
    // Track assignment is dynamic: the CFG builder runs a global sweep (see
    // DisassemblyCFG.cpp Pass 3) and gives every edge a lane 0..kMaxLanes-1
    // such that two edges whose vertical spans overlap never share a track.
    // Each nesting level moves the vertical traversal column kCfaNestStep px
    // further left (laneX), so overlapping edges are drawn side by side,
    // never on top of each other.
    static constexpr int kCfaMarginDefault = 78; // dedicated CFG margin width
    static constexpr int kCfaMinMargin     = 72; // smallest margin that fits all tracks
    static constexpr int kCfaLaneInset     = 70; // x of lane 0 (closest to text)
    static constexpr int kCfaNestStep      = 11; // px shifted left per nesting level
    static constexpr int kCfaLineWidth     = 2;  // edge line thickness
    static constexpr int kCfaSelBoost      = 1;  // extra px for the selected edge
    static constexpr int kCfaSafetyPad     = 4;  // px of clip/paint safety margin
    static constexpr int kCfaHeadLen       = 6;  // triangle arrowhead length
    static constexpr int kCfaHeadW         = 6;  // triangle arrowhead width (even -> integer coords)
    static constexpr int kCfaStopW         = 3;  // return-stop half width
    // The deepest nesting level must stay inside the margin.
    static_assert(kCfaLaneInset - (cfg::kCFAMaxTracks - 1) * kCfaNestStep >= 2,
                  "CFA lanes/arrowheads overflow the gutter");

    // Builds/rebuilds the control-flow graph over the current model rows.
    void buildCFG();
    void paintBlockBackdrop(QPainter& painter, int first, int last,
                            int cellH, int scrollY, int vpW);
    void paintCfaGutter(QPainter& painter, int first, int last,
                        int cellH, int scrollY);
    // Returns the most specific drawn edge under the cursor, or nullptr.
    const cfg::CfaEdge* edgeAt(const QPoint& pos);
    // Sets the neon-highlighted edge (nullptr clears) and repaints.
    void selectEdge(const cfg::CfaEdge* e);
    // Smoothly slides the vertical scroll so `row` is vertically centered,
    // then finalizes caret/address state with `destAddr`.
    void animateScrollToRow(int row, uint64_t destAddr);
    // Finalizes currentRow_/currentAddr_ and broadcasts after the slide.
    void finishNavTo(int row, uint64_t destAddr);

    // --- CFA render pipeline: scope filter -> viewport cull -> track sweep ---
    // A per-window cache of the edges that will actually be drawn this frame.
    // paintEvent and the hit-test operate only on this list, so the margin
    // never shows out-of-function or off-screen lines (no "spaghetti").
    struct CfaDrawItem {
        const cfg::CfaEdge* edge = nullptr; // into cfg_.edges() (stable while cfgValid_)
        int lane = 0;
    };
    std::vector<CfaDrawItem> cfaDrawList_;
    int cfaWindowFirst_ = 0;   // model-row window the list was built for
    int cfaWindowLast_ = -1;
    uint64_t cfaScopeStart_ = 0; // function scope the list was built for
    uint64_t cfaScopeEnd_ = 0;
    uint64_t scopeLanesStart_ = 0; // function scope the lane map was built for
    uint64_t scopeLanesEnd_ = 0;
    // Function-scope lane map (interval graph coloring): one stable column per
    // intra-function jump, recycled as spans terminate; the per-window draw
    // list above only culls against the viewport, never re-colors.
    std::unordered_map<const cfg::CfaEdge*, int> scopeLanes_;
    bool cfaDrawValid_ = false;
    std::vector<uint64_t> funcStarts_; // function entry addresses (sorted)
    uint64_t funcEndMax_ = 0;          // highest instruction address in the index

    // Rebuilds the draw list for the given model-row window (function scope
    // anchor = window center row): scope filter -> viewport cull ->
    // dynamic assignTracks over the survivors only.
    void rebuildCfaDrawList(int firstRow, int lastRow);
    // No-op unless the window or resolved function scope changed.
    void ensureCfaDrawList(int firstRow, int lastRow);
    // Enclosing [start,end] address range of the function containing `addr`;
    // unbounded when no function boundaries are known.
    void funcRangeFor(uint64_t addr, uint64_t& start, uint64_t& end) const;
    // Orthogonal Ghidra-style route for a resolved edge in viewport space:
    // 4 points - exit start on the text boundary, exit corner at the nesting
    // column, traversal corner at the target row, entry tip back on the text
    // boundary. The arrowhead is drawn at the tip pointing into the target.
    // `lane` is the render-time track (from the draw list, not the static one).
    std::vector<QPoint> cfaRoute(const cfg::CfaEdge& edge, int lane,
                                 int cellH, int scrollY) const;
    // Jump to an exact address like the double-click jump (seek + broadcast).
    void jumpToAddress(uint64_t target);

    std::vector<FallbackLine> fallbackLines_;
    QString fallbackText_;

    std::unordered_map<uint64_t, DecodedInstruction> decodedCache_;

    cfg::DisassemblyCFG cfg_;
    bool cfgValid_ = false;

    // Rendering / caret state
    CursorPos anchor_;
    CursorPos caret_;
    int currentRow_ = 0;
    uint64_t currentAddr_ = 0;
    bool selecting_ = false;
    bool dragging_ = false;
    SelectedToken selectedToken_;
    QString highlightWord_;
    TokenKind highlightKind_ = TokenKind::Plain;
    bool synced_ = true;
    int cfaMarginPx_ = kCfaMarginDefault;
    const cfg::CfaEdge* selectedEdge_ = nullptr; // neon-highlighted edge (single click)
    QPropertyAnimation* scrollAnim_ = nullptr;   // smooth double-click slide

    SelectionManager* selectionMgr_ = nullptr;
    SelectionState currentSelection_;

    QTimer* caretBlinkTimer_ = nullptr;
    bool caretVisible_ = true;
    int maxColsSeen_ = 0;
    mutable std::vector<Token> scratchTokens_; // transient tokens for comment/header rows

    QString searchQuery_;
    bool searchMatchCase_ = false;
    int searchActiveRow_ = -1;
};
