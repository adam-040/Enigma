#pragma once

#include "FieldView.h"
#include <cstdint>
#include <vector>
#include <QVector>

namespace ghidra { class ProgramDB; }
namespace ghidra::patch { class PatchMemory; }

struct HexEditUndoEntry {
    uint64_t addr;
    uint8_t oldValue;
    uint8_t newValue;
};

struct HexSearchMatch {
    int line;
    int byteStart;
    int byteEnd;
};

class HexView : public FieldView {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);
    void setData(uint64_t baseAddr, const std::vector<uint8_t>& data);
    void buildFullHex(ghidra::ProgramDB* program, const QString& binaryPath = QString());
    bool containsAddress(uint64_t addr) const;
    void clear();

    void setPatchMemory(ghidra::patch::PatchMemory* pm) { patchMemory_ = pm; }

    bool canUndo() const { return !undoStack_.isEmpty(); }
    bool canRedo() const { return !redoStack_.isEmpty(); }

    void setSearchHighlights(const QVector<HexSearchMatch>& matches);
    void clearSearchHighlights();

    void toggleBookmark(uint64_t addr);
    bool isBookmarked(uint64_t addr) const;
    const QVector<uint64_t>& bookmarks() const { return bookmarks_; }
    void navigateBookmark(bool forward);

signals:
    void patchByteRequested(uint64_t addr);
    void patchNopFillRequested(uint64_t startAddr, uint64_t endAddr);
    void patchStringRequested(uint64_t addr);
    void byteEditRequested(uint64_t addr, uint8_t oldValue, uint8_t newValue);
    void undoRequested(uint64_t addr, uint8_t oldValue);
    void redoRequested(uint64_t addr, uint8_t newValue);
    void bytesPasted(uint64_t startAddr, int count);

public slots:
    bool undoLastEdit();
    bool redoLastEdit();
    void pasteFromClipboard();

protected:
    void paintEvent(QPaintEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    int gutterWidth() const override { return 0; }

private:
    int byteIndexAt(int line, int col) const;
    uint64_t addressForByteToken(int line, int col) const;
    void pushUndo(uint64_t addr, uint8_t oldVal, uint8_t newVal);
    void commitByte(uint64_t addr, uint8_t newByte);
    void advanceCaretAfterEdit();
    bool isHexDigit(int key) const;
    int hexDigitValue(int key) const;
    void clearEditState();
    int byteColumnAt(int line, int byteIdx) const;

    uint64_t baseAddr_ = 0;
    uint64_t endAddr_ = 0;
    ghidra::patch::PatchMemory* patchMemory_ = nullptr;

    // Inline editing state
    bool editing_ = false;
    uint64_t editAddr_ = 0;
    int editLine_ = -1;
    int editByteIdx_ = -1;
    int editCol_ = -1;
    int editNibble_ = 0;
    uint8_t editAccumulator_ = 0;

    // Undo/redo
    QVector<HexEditUndoEntry> undoStack_;
    QVector<HexEditUndoEntry> redoStack_;
    static const int kMaxUndoEntries = 10000;

    // Search highlights
    QVector<HexSearchMatch> searchMatches_;

    // Bookmarks
    QVector<uint64_t> bookmarks_;
};
