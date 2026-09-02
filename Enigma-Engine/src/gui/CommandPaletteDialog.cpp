#include "CommandPaletteDialog.h"
#include "MainWindow.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/Function.h"
#include "ghidra/FunctionIterator.h"

#include <QKeyEvent>
#include <QGraphicsDropShadowEffect>
#include <QPainter>
#include <QStyledItemDelegate>

namespace {

class PaletteItemDelegate : public QStyledItemDelegate {
public:
    explicit PaletteItemDelegate(const std::vector<PaletteItem>& items, QObject* parent = nullptr)
        : QStyledItemDelegate(parent), items_(items) {}

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override {
        int row = index.row();
        if (row < 0 || row >= static_cast<int>(items_.size())) return;
        const PaletteItem& item = items_[row];

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);

        bool isSelected = (option.state & QStyle::State_Selected);

        // Item background
        if (isSelected) {
            painter->fillRect(option.rect, QColor(0x00, 0x78, 0xd4, 30));
            painter->setPen(QPen(QColor(0x00, 0x78, 0xd4), 1));
            painter->drawRoundedRect(option.rect.adjusted(2, 1, -2, -1), 4, 4);
        } else {
            painter->fillRect(option.rect, QColor(0xff, 0xff, 0xff));
        }

        // Category Tag
        QString tagText;
        QColor tagBg, tagFg;
        switch (item.category) {
            case PaletteItem::Category::Function:
                tagText = QStringLiteral("FUNC");
                tagBg = QColor(0xe1, 0xdf, 0xdd);
                tagFg = QColor(0x00, 0x5a, 0x9e);
                break;
            case PaletteItem::Category::Action:
                tagText = QStringLiteral("ACTION");
                tagBg = QColor(0xde, 0xec, 0xf9);
                tagFg = QColor(0x10, 0x6e, 0xbe);
                break;
            case PaletteItem::Category::String:
                tagText = QStringLiteral("STR");
                tagBg = QColor(0xeb, 0xf3, 0xec);
                tagFg = QColor(0x10, 0x7c, 0x10);
                break;
            case PaletteItem::Category::Address:
                tagText = QStringLiteral("ADDR");
                tagBg = QColor(0xff, 0xf4, 0xce);
                tagFg = QColor(0x79, 0x4f, 0x00);
                break;
        }

        QRect r = option.rect.adjusted(10, 0, -10, 0);

        // Draw tag pill
        QFont tagFont = option.font;
        tagFont.setPointSize(8);
        tagFont.setBold(true);
        painter->setFont(tagFont);
        QFontMetrics fmTag(tagFont);
        int tagW = fmTag.horizontalAdvance(tagText) + 10;
        int tagH = 18;
        int tagY = r.top() + (r.height() - tagH) / 2;
        QRect tagRect(r.left(), tagY, tagW, tagH);

        painter->setPen(Qt::NoPen);
        painter->setBrush(tagBg);
        painter->drawRoundedRect(tagRect, 3, 3);
        painter->setPen(tagFg);
        painter->drawText(tagRect, Qt::AlignCenter, tagText);

        // Title
        QFont titleFont = option.font;
        titleFont.setPointSize(10);
        titleFont.setBold(true);
        painter->setFont(titleFont);
        painter->setPen(QColor(0x1e, 0x1e, 0x1e));
        int textX = tagRect.right() + 10;
        QRect titleRect(textX, r.top() + 4, r.width() - textX - 100, 20);
        painter->drawText(titleRect, Qt::AlignLeft | Qt::AlignVCenter, item.title);

        // Subtitle
        if (!item.subtitle.isEmpty()) {
            QFont subFont = option.font;
            subFont.setPointSize(8);
            painter->setFont(subFont);
            painter->setPen(QColor(0x60, 0x60, 0x60));
            QRect subRect(textX, r.top() + 22, r.width() - textX - 100, 16);
            painter->drawText(subRect, Qt::AlignLeft | Qt::AlignVCenter, item.subtitle);
        }

        // Shortcut
        if (!item.shortcut.isEmpty()) {
            QFont scFont = option.font;
            scFont.setPointSize(8);
            painter->setFont(scFont);
            painter->setPen(QColor(0x00, 0x78, 0xd4));
            QRect scRect(r.right() - 110, r.top(), 110, r.height());
            painter->drawText(scRect, Qt::AlignRight | Qt::AlignVCenter, item.shortcut);
        }

        painter->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override {
        Q_UNUSED(option)
        Q_UNUSED(index)
        return QSize(100, 44);
    }

private:
    const std::vector<PaletteItem>& items_;
};

} // anonymous namespace

CommandPaletteDialog::CommandPaletteDialog(MainWindow* mainWindow, ghidra::ProgramDB* program, QWidget* parent)
    : QDialog(parent, Qt::FramelessWindowHint | Qt::Popup),
      mainWindow_(mainWindow),
      program_(program)
{
    setAttribute(Qt::WA_TranslucentBackground);
    setFixedSize(580, 420);

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    auto* container = new QWidget(this);
    container->setObjectName(QStringLiteral("paletteContainer"));
    container->setStyleSheet(
        QStringLiteral("#paletteContainer {"
                       "  background: #ffffff;"
                       "  border: 1px solid #c8c8c8;"
                       "  border-radius: 8px;"
                       "}"));

    auto* shadow = new QGraphicsDropShadowEffect(container);
    shadow->setBlurRadius(20);
    shadow->setColor(QColor(0, 0, 0, 80));
    shadow->setOffset(0, 4);
    container->setGraphicsEffect(shadow);

    auto* v = new QVBoxLayout(container);
    v->setContentsMargins(12, 12, 12, 12);
    v->setSpacing(8);

    // Search row
    auto* searchRow = new QHBoxLayout();
    searchRow->setSpacing(8);

    auto* searchIcon = new QLabel(QStringLiteral("🔍"), container);
    searchIcon->setStyleSheet(QStringLiteral("font-size: 14px; color: #666666;"));
    searchRow->addWidget(searchIcon);

    searchEdit_ = new QLineEdit(container);
    searchEdit_->setPlaceholderText(tr("Type a command, function, address (0x...), or action..."));
    searchEdit_->setToolTip(tr("Quick access: type a function name, address, or command to navigate"));
    searchEdit_->setStyleSheet(
        QStringLiteral("QLineEdit {"
                       "  background: #f8f9fa;"
                       "  border: 1px solid #dcdcdc;"
                       "  border-radius: 4px;"
                       "  padding: 6px 10px;"
                       "  font-size: 13px;"
                       "  color: #111111;"
                       "}"
                       "QLineEdit:focus {"
                       "  border: 1px solid #0078d4;"
                       "  background: #ffffff;"
                       "}"));
    searchRow->addWidget(searchEdit_, 1);
    v->addLayout(searchRow);

    // Results list
    resultList_ = new QListWidget(container);
    resultList_->setItemDelegate(new PaletteItemDelegate(filteredItems_, this));
    resultList_->setStyleSheet(
        QStringLiteral("QListWidget {"
                       "  background: #ffffff;"
                       "  border: 1px solid #e5e5e5;"
                       "  border-radius: 4px;"
                       "  outline: none;"
                       "}"
                       "QListWidget::item {"
                       "  border-bottom: 1px solid #f0f0f0;"
                       "}"));
    resultList_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    resultList_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    connect(resultList_, &QListWidget::itemActivated, this, &CommandPaletteDialog::onItemActivated);
    v->addWidget(resultList_, 1);

    // Tip label at bottom
    tipLabel_ = new QLabel(tr("↑↓ to navigate • Enter to select • Esc to dismiss"), container);
    tipLabel_->setStyleSheet(QStringLiteral("color: #888888; font-size: 10px; padding: 2px 4px;"));
    v->addWidget(tipLabel_);

    mainLayout->addWidget(container);

    searchEdit_->installEventFilter(this);
    resultList_->installEventFilter(this);

    connect(searchEdit_, &QLineEdit::textChanged, this, &CommandPaletteDialog::onSearchTextChanged);
}

void CommandPaletteDialog::showPalette() {
    populateItems();
    searchEdit_->clear();
    filterItems(QString());

    if (mainWindow_) {
        // Center near top of MainWindow
        QPoint mainCenter = mainWindow_->mapToGlobal(QPoint(mainWindow_->width() / 2, mainWindow_->height() / 4));
        move(mainCenter.x() - width() / 2, mainCenter.y());
    }

    show();
    raise();
    activateWindow();
    searchEdit_->setFocus();
}

void CommandPaletteDialog::populateItems() {
    allItems_.clear();

    // 1. Actions
    auto addAction = [this](const QString& title, const QString& subtitle, const QString& shortcut, std::function<void()> fn) {
        allItems_.push_back({PaletteItem::Category::Action, title, subtitle, shortcut, std::move(fn)});
    };

    addAction(tr("Find in Disassembly"), tr("Open interactive search bar in disassembly view"), tr("Ctrl+F"), [this]() {
        if (mainWindow_) mainWindow_->openDisassemblyFind();
    });
    addAction(tr("Go to Address / Symbol"), tr("Navigate to address, symbol, or relative offset"), tr("G"), [this]() {
        if (mainWindow_) mainWindow_->onGoToAddress();
    });
    addAction(tr("Cross References (XRefs)"), tr("Inspect all incoming and outgoing references"), tr("X"), [this]() {
        if (mainWindow_) mainWindow_->onShowCrossReferences();
    });
    addAction(tr("Rename Function"), tr("Modify function symbol name"), tr("N"), [this]() {
        if (mainWindow_) mainWindow_->onRenameFunction();
    });
    addAction(tr("Set Function Type / Signature"), tr("Edit function prototype and return type"), tr("Y"), [this]() {
        if (mainWindow_) mainWindow_->onSetFunctionSignature();
    });
    addAction(tr("Toggle View Focus"), tr("Switch focus between Disassembly and Decompiler"), tr("Tab"), [this]() {
        if (mainWindow_) mainWindow_->onToggleDecompilerFocus();
    });
    addAction(tr("Add Label"), tr("Create a new code label at current address"), tr("L"), [this]() {
        if (mainWindow_) mainWindow_->onAddLabel();
    });
    addAction(tr("Set Comment"), tr("Add or edit inline disassembly comment"), tr(";"), [this]() {
        if (mainWindow_) mainWindow_->onSetComment();
    });
    addAction(tr("Add Bookmark"), tr("Toggle bookmark at address"), tr("B"), [this]() {
        if (mainWindow_) mainWindow_->onAddBookmark();
    });
    addAction(tr("Commit Repository Changes"), tr("Save snapshot to version control repository"), tr("Ctrl+K"), [this]() {
        if (mainWindow_) mainWindow_->onCommit();
    });
    addAction(tr("Help & Shortcuts Reference"), tr("View complete reverse engineering cheatsheet"), QString(), [this]() {
        if (mainWindow_) mainWindow_->onShowHelp();
    });

    // 2. Functions from ProgramDB
    if (program_ && program_->getFunctionManager()) {
        auto iter = program_->getFunctionManager()->getFunctions(true);
        while (iter.hasNext()) {
            auto* fn = iter.next();
            if (!fn) continue;
            uint64_t entry = fn->getEntryPoint().getOffset();
            QString name = QString::fromStdString(fn->getName());
            QString sig = QString::fromStdString(fn->getSignatureString());
            QString subtitle = QStringLiteral("0x%1").arg(entry, 0, 16);
            if (!sig.isEmpty()) subtitle += QStringLiteral(" • ") + sig;

            allItems_.push_back({
                PaletteItem::Category::Function,
                name,
                subtitle,
                QStringLiteral("0x%1").arg(entry, 0, 16),
                [this, entry, name]() {
                    if (mainWindow_) mainWindow_->navigateTo(entry, name, true);
                }
            });
        }
    }
}

void CommandPaletteDialog::filterItems(const QString& query) {
    filteredItems_.clear();
    resultList_->clear();

    QString q = query.trimmed();

    // Check if query is an address or offset
    bool isAddr = false;
    uint64_t parsedAddr = 0;
    if (q.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
        parsedAddr = q.mid(2).toULongLong(&isAddr, 16);
    } else if (!q.isEmpty() && q.length() >= 4 && (q.startsWith(QLatin1Char('+')) || q.startsWith(QLatin1Char('-')) || q[0].isDigit())) {
        if (q.startsWith(QLatin1Char('+')) || q.startsWith(QLatin1Char('-'))) {
            // relative
            bool relOk = false;
            int64_t rel = q.toLongLong(&relOk, 16);
            if (relOk && mainWindow_) {
                parsedAddr = mainWindow_->currentAddress() + rel;
                isAddr = true;
            }
        } else {
            parsedAddr = q.toULongLong(&isAddr, 16);
        }
    }

    if (isAddr) {
        PaletteItem addrItem;
        addrItem.category = PaletteItem::Category::Address;
        addrItem.title = QStringLiteral("Jump to Address 0x%1").arg(parsedAddr, 0, 16);
        addrItem.subtitle = QStringLiteral("Navigate directly in Disassembly, Hex & Decompiler");
        addrItem.shortcut = QStringLiteral("Enter");
        addrItem.onTrigger = [this, parsedAddr]() {
            if (mainWindow_) mainWindow_->navigateTo(parsedAddr);
        };
        filteredItems_.push_back(addrItem);
    }

    for (const auto& item : allItems_) {
        if (q.isEmpty() ||
            item.title.contains(q, Qt::CaseInsensitive) ||
            item.subtitle.contains(q, Qt::CaseInsensitive) ||
            item.shortcut.contains(q, Qt::CaseInsensitive)) {
            filteredItems_.push_back(item);
            if (filteredItems_.size() >= 100) break; // limit to 100 results for speed
        }
    }

    for (size_t i = 0; i < filteredItems_.size(); ++i) {
        auto* listItem = new QListWidgetItem(resultList_);
        resultList_->addItem(listItem);
    }

    if (resultList_->count() > 0) {
        resultList_->setCurrentRow(0);
    }
}

void CommandPaletteDialog::onSearchTextChanged(const QString& text) {
    filterItems(text);
}

void CommandPaletteDialog::executeCurrent() {
    int row = resultList_->currentRow();
    if (row >= 0 && row < static_cast<int>(filteredItems_.size())) {
        auto fn = filteredItems_[row].onTrigger;
        close();
        if (fn) fn();
    }
}

void CommandPaletteDialog::onItemActivated(QListWidgetItem* item) {
    Q_UNUSED(item)
    executeCurrent();
}

bool CommandPaletteDialog::eventFilter(QObject* obj, QEvent* event) {
    if (event->type() == QEvent::KeyPress) {
        auto* keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->key() == Qt::Key_Down) {
            int row = resultList_->currentRow();
            if (row + 1 < resultList_->count()) {
                resultList_->setCurrentRow(row + 1);
            }
            return true;
        } else if (keyEvent->key() == Qt::Key_Up) {
            int row = resultList_->currentRow();
            if (row > 0) {
                resultList_->setCurrentRow(row - 1);
            }
            return true;
        } else if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter) {
            executeCurrent();
            return true;
        } else if (keyEvent->key() == Qt::Key_Escape) {
            close();
            return true;
        }
    }
    return QDialog::eventFilter(obj, event);
}

void CommandPaletteDialog::keyPressEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Escape) {
        close();
        event->accept();
        return;
    }
    QDialog::keyPressEvent(event);
}
