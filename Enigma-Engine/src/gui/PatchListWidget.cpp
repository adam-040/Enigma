#include "PatchListWidget.h"
#include <ghidra/patch/PatchManager.h>
#include <ghidra/patch/Patch.h>
#include <ghidra/Disassembler.h>
#include <QHeaderView>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QApplication>

namespace {
QString toHex(const std::vector<uint8_t>& bytes) {
    QString s;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i) s += ' ';
        s += QString("%1").arg(bytes[i], 2, 16, QChar('0'));
    }
    return s;
}
} // namespace

PatchListWidget::PatchListWidget(QWidget* parent)
    : QTableWidget(parent)
{
    setColumnCount(ColCount);
    setHorizontalHeaderLabels({"Address", "From", "To", "Name", "Status"});
    setWordWrap(false);
    setShowGrid(false);
    setAlternatingRowColors(true);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setContextMenuPolicy(Qt::DefaultContextMenu);
    verticalHeader()->setVisible(false);
    verticalHeader()->setDefaultSectionSize(24);

    QHeaderView* header = horizontalHeader();
    QFont headerFont = QApplication::font();
    headerFont.setWeight(QFont::Normal);
    header->setFont(headerFont);
    header->setSectionsMovable(false);
    header->setHighlightSections(false);
    header->setSortIndicatorShown(false);
    header->setStretchLastSection(true);
    for (int c = 0; c < ColCount; ++c)
        header->setSectionResizeMode(c, QHeaderView::Interactive);
    header->resizeSection(ColAddress, 110);
    header->resizeSection(ColFrom, 160);
    header->resizeSection(ColTo, 160);
    header->resizeSection(ColName, 200);
    header->resizeSection(ColStatus, 80);
}

PatchListWidget::~PatchListWidget() = default;

void PatchListWidget::setPatchManager(ghidra::patch::PatchManager* pm) {
    patchMgr_ = pm;
    if (!patchMgr_) return;
    using PC = ghidra::patch::PatchManager;
    patchMgr_->setOnPatchAdded([this](const ghidra::patch::PatchId&) { refresh(); });
    patchMgr_->setOnPatchRemoved([this](const ghidra::patch::PatchId&) { refresh(); });
    patchMgr_->setOnPatchEnabled([this](const ghidra::patch::PatchId&) { refresh(); });
    patchMgr_->setOnPatchDisabled([this](const ghidra::patch::PatchId&) { refresh(); });
    refresh();
}

void PatchListWidget::setDisassembler(std::unique_ptr<ghidra::Disassembler> disasm) {
    disasm_ = std::move(disasm);
    refresh();
}

QString PatchListWidget::instructionText(const std::vector<uint8_t>& bytes,
                                         uint64_t addr) const {
    if (disasm_ && !bytes.empty()) {
        try {
            auto inst = disasm_->disassembleOne(bytes, addr);
            if (inst.length > 0 && !inst.mnemonic.empty()) {
                QString text = QString::fromStdString(inst.mnemonic).toUpper();
                for (const auto& op : inst.operands) {
                    if (!op.empty()) {
                        text += ' ';
                        text += QString::fromStdString(op);
                    }
                }
                return text;
            }
        } catch (...) {
        }
    }
    return toHex(bytes);
}

void PatchListWidget::refresh() {
    QFont headerFont = QApplication::font();
    headerFont.setWeight(QFont::Normal);
    horizontalHeader()->setFont(headerFont);

    clearContents();
    setRowCount(0);
    if (!patchMgr_) return;

    auto patches = patchMgr_->getAllPatches();
    std::sort(patches.begin(), patches.end(), [](const ghidra::patch::Patch* a,
                                                 const ghidra::patch::Patch* b) {
        return a->baseAddress() < b->baseAddress();
    });

    setRowCount(static_cast<int>(patches.size()));
    for (int i = 0; i < static_cast<int>(patches.size()); ++i) {
        const ghidra::patch::Patch* p = patches[i];
        uint64_t addr = p->baseAddress();
        const bool active = p->enabled() && p->applied();

        auto* addrItem = new QTableWidgetItem(QString("0x%1").arg(addr, 0, 16));
        auto* fromItem = new QTableWidgetItem(instructionText(p->originalBytes(), addr));
        auto* toItem = new QTableWidgetItem(instructionText(p->patchedBytes(), addr));
        auto* nameItem = new QTableWidgetItem(QString::fromStdString(p->name()));
        auto* statusItem = new QTableWidgetItem(active ? QString("Active") : QString("Disabled"));

        fromItem->setToolTip("From: " + toHex(p->originalBytes()));
        toItem->setToolTip("To: " + toHex(p->patchedBytes()));
        addrItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(addr));
        addrItem->setData(Qt::UserRole + 1, QString::fromStdString(p->id().id));

        setItem(i, ColAddress, addrItem);
        setItem(i, ColFrom, fromItem);
        setItem(i, ColTo, toItem);
        setItem(i, ColName, nameItem);
        setItem(i, ColStatus, statusItem);
    }
}

QString PatchListWidget::idAtRow(int row) const {
    QTableWidgetItem* idItem = item(row, ColAddress);
    return idItem ? idItem->data(Qt::UserRole + 1).toString() : QString();
}

void PatchListWidget::mouseDoubleClickEvent(QMouseEvent* event) {
    int row = rowAt(event->pos().y());
    if (row >= 0) {
        QTableWidgetItem* addrItem = item(row, ColAddress);
        if (addrItem)
            emit navigateRequested(addrItem->data(Qt::UserRole).toULongLong());
    }
    QTableWidget::mouseDoubleClickEvent(event);
}

void PatchListWidget::contextMenuEvent(QContextMenuEvent* event) {
    int row = rowAt(event->pos().y());
    if (row < 0) return;
    QString id = idAtRow(row);
    if (id.isEmpty()) return;
    setCurrentCell(row, ColAddress);

    QMenu menu(this);
    QAction* actNavigate = menu.addAction(tr("Navigate to Address"));
    menu.addSeparator();
    QAction* actToggle = menu.addAction(tr("Toggle Enable/Disable"));
    QAction* actDelete = menu.addAction(tr("Delete Patch"));
    QAction* chosen = menu.exec(event->globalPos());
    if (chosen == actNavigate) {
        QTableWidgetItem* addrItem = item(row, ColAddress);
        if (addrItem)
            emit navigateRequested(addrItem->data(Qt::UserRole).toULongLong());
    } else if (chosen == actToggle) {
        emit patchToggled(id);
    } else if (chosen == actDelete) {
        emit patchDeleted(id);
    }
}

void PatchListWidget::keyPressEvent(QKeyEvent* event) {
    int row = currentRow();
    if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
        if (row >= 0) {
            QTableWidgetItem* addrItem = item(row, ColAddress);
            if (addrItem)
                emit navigateRequested(addrItem->data(Qt::UserRole).toULongLong());
        }
        return;
    }
    if (event->key() == Qt::Key_Delete && row >= 0) {
        QString id = idAtRow(row);
        if (!id.isEmpty()) emit patchDeleted(id);
        return;
    }
    QTableWidget::keyPressEvent(event);
}
