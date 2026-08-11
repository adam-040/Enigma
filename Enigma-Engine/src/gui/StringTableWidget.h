#pragma once

#include <QTableWidget>
#include <cstdint>
#include <QString>

namespace ghidra { class ProgramDB; }

/// Table of all strings discovered in the loaded binary.
/// Columns: Address, String, Length, Encoding, Labels, Xrefs.
/// Double-click navigates the disassembly to the string address.
class StringTableWidget : public QTableWidget {
    Q_OBJECT
public:
    enum Column {
        ColAddress = 0,
        ColString,
        ColLength,
        ColEncoding,
        ColLabels,
        ColXrefs,
        ColCount,
    };

    explicit StringTableWidget(QWidget* parent = nullptr);
    ~StringTableWidget() override;

    void refresh(ghidra::ProgramDB* program);
    void setFilter(const QString& text);
    void clearContentsAndRows();

signals:
    void navigateRequested(uint64_t addr);

protected:
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;

private:
    void applyFilter();
    uint64_t addrAtRow(int row) const;

    QString filterText_;
};

class StringTableFilterBar : public QWidget {
    Q_OBJECT
public:
    explicit StringTableFilterBar(StringTableWidget* table, QWidget* parent = nullptr);

private:
    StringTableWidget* table_;
};
