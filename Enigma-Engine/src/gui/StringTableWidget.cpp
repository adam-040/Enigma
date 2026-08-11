#include "StringTableWidget.h"

#include <ghidra/ProgramDB.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Scalar.h>
#include <ghidra/Instruction.h>

#include <QHeaderView>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QLabel>
#include <cstdlib>
#include <algorithm>
#include <unordered_set>

namespace {

QString byteString(const std::vector<uint8_t>& bytes) {
    QString s;
    s.reserve(bytes.size() * 4 + 2);
    s += '"';
    for (uint8_t b : bytes) {
        if (b == '"') {
            s += "\\\"";
        } else if (b == '\\') {
            s += "\\\\";
        } else if (b >= 0x20 && b < 0x7F) {
            s += QChar(b);
        } else if (b == '\n') {
            s += "\\n";
        } else if (b == '\r') {
            s += "\\r";
        } else if (b == '\t') {
            s += "\\t";
        } else {
            s += QString("\\x%1").arg(b, 2, 16, QChar('0'));
        }
    }
    s += '"';
    return s;
}

QString encodingFor(ghidra::Data* data) {
    const std::string& name = data->getDataType()->getName();
    if (name.find("Unicode") != std::string::npos || name.find("UTF16") != std::string::npos ||
        name.find("WCHAR") != std::string::npos) {
        return QStringLiteral("UTF-16");
    }
    if (name.find("UTF8") != std::string::npos) {
        return QStringLiteral("UTF-8");
    }
    if (name.find("Pascal") != std::string::npos) {
        return QStringLiteral("Pascal");
    }
    return QStringLiteral("ASCII");
}

} // namespace

StringTableWidget::StringTableWidget(QWidget* parent)
    : QTableWidget(parent)
{
    setColumnCount(ColCount);
    setHorizontalHeaderLabels({"Address", "String", "Length", "Encoding", "Labels", "Xrefs"});
    setWordWrap(false);
    setShowGrid(false);
    setAlternatingRowColors(true);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setContextMenuPolicy(Qt::DefaultContextMenu);
    setSortingEnabled(true);
    verticalHeader()->setVisible(false);
    verticalHeader()->setDefaultSectionSize(22);

    QHeaderView* header = horizontalHeader();
    QFont headerFont = QApplication::font();
    headerFont.setWeight(QFont::Normal);
    header->setFont(headerFont);
    header->setSectionsMovable(false);
    header->setHighlightSections(false);
    header->setSortIndicatorShown(true);
    header->setSortIndicator(ColAddress, Qt::AscendingOrder);
    header->setStretchLastSection(true);
    for (int c = 0; c < ColCount; ++c) {
        header->setSectionResizeMode(c, QHeaderView::Interactive);
    }
    header->resizeSection(ColAddress, 110);
    header->resizeSection(ColString, 320);
    header->resizeSection(ColLength, 60);
    header->resizeSection(ColEncoding, 70);
    header->resizeSection(ColLabels, 150);
    header->resizeSection(ColXrefs, 50);
}

StringTableWidget::~StringTableWidget() = default;

void StringTableWidget::refresh(ghidra::ProgramDB* program) {
    if (!program) return;
    auto* listing = program->getListing();
    if (!listing) return;
    auto* memory = program->getMemory();
    if (!memory) return;

    struct StringEntry {
        uint64_t address = 0;
        QString text;
        int length = 0;
        QString encoding;
        QString labels;
        int xrefs = 0;
    };
    std::vector<StringEntry> entries;

    auto* af = program->getAddressFactory();
    auto* symTable = program->getSymbolTable();

    ghidra::AddressSet allAddr;
    for (auto* block : memory->getBlocks()) {
        if (block) allAddr.add(block->getStart(), block->getEnd());
    }
    auto allData = listing->getData(allAddr);
    for (ghidra::Data* d : allData) {
        if (!d || !d->isString()) continue;
        uint64_t addr = d->getAddress().getUnsignedOffset();
        int length = d->getLength();
        if (length <= 0) continue;

        ghidra::Address gAddr = af->oldGetAddressFromLong(addr);
        std::vector<uint8_t> bytes(length);
        int got = 0;
        try {
            got = memory->getBytes(gAddr, bytes.data(), length);
        } catch (...) {
            got = 0;
        }
        if (got <= 0) continue;
        bytes.resize(got);

        StringEntry e;
        e.address = addr;
        e.text = byteString(bytes);
        e.length = length;
        e.encoding = encodingFor(d);
        if (symTable) {
            auto syms = symTable->getSymbols(gAddr);
            QStringList names;
            for (const auto* s : syms) {
                if (s) names << QString::fromStdString(s->getName());
            }
            e.labels = names.isEmpty()
                ? QStringLiteral("str_0x%1").arg(addr, 0, 16)
                : names.join(", ");
        }
        auto* refMgr = program->getReferenceManager();
        if (refMgr) {
            e.xrefs = static_cast<int>(refMgr->getReferencesTo(gAddr).size());
        }
        entries.push_back(std::move(e));
    }

    std::sort(entries.begin(), entries.end(),
        [](const StringEntry& a, const StringEntry& b) { return a.address < b.address; });

    clearContentsAndRows();
    setRowCount(static_cast<int>(entries.size()));
    for (int i = 0; i < static_cast<int>(entries.size()); ++i) {
        const StringEntry& e = entries[i];

        auto* addrItem = new QTableWidgetItem(QStringLiteral("0x%1").arg(e.address, 0, 16));
        addrItem->setData(Qt::UserRole, static_cast<qlonglong>(e.address));
        addrItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        addrItem->setFont(QApplication::font());
        setItem(i, ColAddress, addrItem);

        auto* textItem = new QTableWidgetItem(e.text);
        textItem->setFont(QApplication::font());
        textItem->setToolTip(e.text);
        setItem(i, ColString, textItem);

        auto* lenItem = new QTableWidgetItem(QString::number(e.length));
        lenItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        setItem(i, ColLength, lenItem);

        auto* encItem = new QTableWidgetItem(e.encoding);
        setItem(i, ColEncoding, encItem);

        auto* labelItem = new QTableWidgetItem(e.labels);
        setItem(i, ColLabels, labelItem);

        auto* xrefItem = new QTableWidgetItem(QString::number(e.xrefs));
        xrefItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        setItem(i, ColXrefs, xrefItem);
    }

    applyFilter();
}

void StringTableWidget::clearContentsAndRows() {
    blockSignals(true);
    clearContents();
    setRowCount(0);
    blockSignals(false);
}

void StringTableWidget::setFilter(const QString& text) {
    filterText_ = text;
    applyFilter();
}

void StringTableWidget::applyFilter() {
    const QString needle = filterText_.trimmed();
    for (int i = 0; i < rowCount(); ++i) {
        bool match = needle.isEmpty();
        if (!match) {
            for (int c = 0; c < ColCount; ++c) {
                QTableWidgetItem* it = item(i, c);
                if (it && it->text().contains(needle, Qt::CaseInsensitive)) {
                    match = true;
                    break;
                }
            }
        }
        setRowHidden(i, !match);
    }
}

uint64_t StringTableWidget::addrAtRow(int row) const {
    if (row < 0 || row >= rowCount()) return 0;
    QTableWidgetItem* it = item(row, ColAddress);
    if (!it) return 0;
    return static_cast<uint64_t>(it->data(Qt::UserRole).toLongLong());
}

void StringTableWidget::mouseDoubleClickEvent(QMouseEvent* event) {
    QTableWidget::mouseDoubleClickEvent(event);
    int row = currentRow();
    uint64_t addr = addrAtRow(row);
    if (addr != 0) emit navigateRequested(addr);
}

void StringTableWidget::contextMenuEvent(QContextMenuEvent* event) {
    QTableWidgetItem* hit = itemAt(event->pos());
    if (hit) setCurrentItem(hit);

    QMenu menu(this);
    QAction* copyAddr = menu.addAction(tr("Copy Address"));
    QAction* copyString = menu.addAction(tr("Copy String"));
    QAction* navigate = menu.addAction(tr("Navigate to Address"));
    QAction* chosen = menu.exec(event->globalPos());
    if (!chosen) return;

    int row = currentRow();
    uint64_t addr = addrAtRow(row);
    QTableWidgetItem* strItem = (row >= 0) ? item(row, ColString) : nullptr;

    if (chosen == copyAddr && addr != 0)
        QApplication::clipboard()->setText(QStringLiteral("0x%1").arg(addr, 0, 16));
    else if (chosen == copyString && strItem)
        QApplication::clipboard()->setText(strItem->text());
    else if (chosen == navigate && addr != 0)
        emit navigateRequested(addr);
}

void StringTableWidget::keyPressEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
        uint64_t addr = addrAtRow(currentRow());
        if (addr != 0) emit navigateRequested(addr);
        return;
    }
    QTableWidget::keyPressEvent(event);
}

StringTableFilterBar::StringTableFilterBar(StringTableWidget* table, QWidget* parent)
    : QWidget(parent)
    , table_(table)
{
    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(4, 2, 4, 2);
    layout->setSpacing(6);

    auto* label = new QLabel(tr("Filter:"), this);
    auto* filter = new QLineEdit(this);
    filter->setClearButtonEnabled(true);
    filter->setPlaceholderText(tr("Search strings..."));
    layout->addWidget(label);
    layout->addWidget(filter, 1);

    connect(filter, &QLineEdit::textChanged, table_, &StringTableWidget::setFilter);
}
