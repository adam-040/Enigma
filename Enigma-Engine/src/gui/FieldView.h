#pragma once

#include <QAbstractScrollArea>
#include <QFont>
#include <QString>
#include <QVector>
#include <QPair>
#include <QColor>
#include <algorithm>
#include <memory>
#include <vector>
#include <cstdint>
#include <climits>
#include <QTimer>
#include <QFocusEvent>
#include "gui/CutterSeekable.h"
#include "SelectionState.h"

class SelectionManager;

struct Token {
    QString text;
    TokenKind kind = TokenKind::Plain;
    uint64_t addr = 0;
    uint64_t refTarget = 0;
    int startCol = 0;
    int len = 0;
    int spaceAfter = 0; // columns of whitespace that follow this token in the line
    int byteIndex = -1;   // 0-15 for hex/ascii data bytes, -1 for other tokens
};

struct Line {
    uint64_t addr = 0;
    int indent = 0;
    QVector<Token> tokens;
    std::vector<uint8_t> bytes;
    QString text;
};

class Document {
public:
    void clear();
    void addLine(Line line);
    void finalize();
    int lineCount() const { return lines_.size(); }
    int maxColumns() const { return maxColumns_; }
    const Line& line(int idx) const { return lines_[idx]; }
    int lineForAddress(uint64_t addr) const;
    uint64_t addressForLine(int idx) const;
    std::pair<uint64_t, uint64_t> instructionRangeForAddress(uint64_t addr) const;
private:
    QVector<Line> lines_;
    QVector<QPair<uint64_t, int>> addrIndex_;
    int maxColumns_ = 0;
};

class FieldView : public QAbstractScrollArea, public CutterSeekable {
    Q_OBJECT
public:
    explicit FieldView(QWidget* parent = nullptr);

    void setDocument(std::unique_ptr<Document> doc);
    void clearDocument();
    uint64_t addressAtCurrentLine() const;

    void seek(uint64_t addr) override;
    uint64_t currentAddress() const override { return currentAddr_; }
    void setSyncState(bool synced) override { synced_ = synced; }
    bool syncState() const override { return synced_; }

    void setSelectionManager(SelectionManager* mgr);
    SelectionManager* selectionManager() const { return selectionMgr_; }
    SelectionState currentSelection() const { return currentSelection_; }
    const Document* document() const { return doc_.get(); }

signals:
    void seekRequested(uint64_t addr);
    void cursorAddressChanged(uint64_t addr);
    void showReferencesRequested(uint64_t addr, bool to);

public slots:
    virtual void applySelection(const SelectionState& sel);

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

    virtual QColor colorForKind(TokenKind kind) const;
    virtual bool isBoldKind(TokenKind kind) const;

    int visibleLineCount() const;
    void setHeaderHeight(int h) { headerHeight_ = h; }

    struct SelectedToken {
        int line = -1;
        int startCol = -1;
        int len = 0;
        bool contains(int l, int c) const {
            return line == l && c >= startCol && c < startCol + len;
        }
        bool operator==(const SelectedToken& o) const {
            return line == o.line && startCol == o.startCol && len == o.len;
        }
        bool operator!=(const SelectedToken& o) const { return !(*this == o); }
    };
    SelectedToken selectedToken_;
    int headerHeight_ = 0;
    int anchorLine() const { return anchor_.line; }
    int anchorCol() const { return anchor_.col; }
    int caretLine() const { return caret_.line; }
    int caretCol() const { return caret_.col; }
    int currentLineIndex() const { return currentLine_; }
    bool isCaretVisible() const { return caretVisible_; }

protected:
    struct CursorPos {
        int line = 0; int col = 0;
        bool operator==(const CursorPos& o) const { return line == o.line && col == o.col; }
        bool operator!=(const CursorPos& o) const { return !(*this == o); }
    };
    struct HitResult { int line; int col; };

    HitResult caretAtPos(const QPoint& pos) const;
    const Token* tokenAt(int line, int col) const;
    int tokenIndexAt(int line, int col) const;
    void selectTokenAt(int line, int col);
    void updateScrollBars();
    void ensureVisible(int line);
    void selectAll();
    void copySelection();
    void resetCaretBlink();
    virtual int gutterWidth() const;
    const Token* findTokenByAddressAndText(uint64_t addr, const QString& text, TokenKind kind) const;

    std::unique_ptr<Document> doc_;
    int charWidth_ = 8;
    int lineHeight_ = 20;
    int ascent_ = 14;
    int leftPad_ = 8;
    bool boldSameWidth_ = true;

    CursorPos anchor_;
    CursorPos caret_;
    int currentLine_ = 0;
    uint64_t currentAddr_ = 0;
    bool selecting_ = false;

    QString highlightWord_;
    TokenKind highlightKind_ = TokenKind::Plain;
    bool synced_ = true;

    SelectionManager* selectionMgr_ = nullptr;
    SelectionState currentSelection_;

    QTimer* caretBlinkTimer_ = nullptr;
    bool caretVisible_ = true;
    bool dragging_ = false;
};
