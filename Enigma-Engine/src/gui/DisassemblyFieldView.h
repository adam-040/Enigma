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
#include "gui/CutterSeekable.h"
#include "SelectionState.h"

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

signals:
    void seekRequested(uint64_t addr);
    void cursorAddressChanged(uint64_t addr);
    void addressJumpRequested(uint64_t addr);
    void patchInstructionRequested(uint64_t addr, const QString& currentMnemonic,
                                   const QString& currentOperands);
    void showReferencesRequested(uint64_t addr, bool to);
    void exportPatchedRequested();

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
    static bool isBranchMnemonic(const QString& mne);
    static QString formatBytes(const std::vector<uint8_t>& bytes);
    static bool isCommentLine(const QString& trimmed);
    static std::vector<uint8_t> fetchBytesLocal(ghidra::ProgramDB* program, uint64_t addr, int len);

    int lineCount() const; // instructions+headers+gaps in index mode, fallback lines otherwise
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
    QString lineText(int row) const;
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

    static constexpr int kGutterWidth = 12; // patch-marker gutter

    std::vector<FallbackLine> fallbackLines_;
    QString fallbackText_;

    std::unordered_map<uint64_t, DecodedInstruction> decodedCache_;

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

    SelectionManager* selectionMgr_ = nullptr;
    SelectionState currentSelection_;

    QTimer* caretBlinkTimer_ = nullptr;
    bool caretVisible_ = true;
    int maxColsSeen_ = 0;
    mutable std::vector<Token> scratchTokens_; // transient tokens for comment/header rows
};
