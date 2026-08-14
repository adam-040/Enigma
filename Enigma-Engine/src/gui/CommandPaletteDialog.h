#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QListWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QString>
#include <vector>
#include <functional>

namespace ghidra {
class ProgramDB;
}

class MainWindow;

struct PaletteItem {
    enum class Category {
        Function,
        String,
        Action,
        Address
    };

    Category category;
    QString title;
    QString subtitle;
    QString shortcut;
    std::function<void()> onTrigger;
};

class CommandPaletteDialog : public QDialog {
    Q_OBJECT
public:
    explicit CommandPaletteDialog(MainWindow* mainWindow, ghidra::ProgramDB* program = nullptr, QWidget* parent = nullptr);

    void showPalette();

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;

private slots:
    void onSearchTextChanged(const QString& text);
    void onItemActivated(QListWidgetItem* item);

private:
    void populateItems();
    void filterItems(const QString& query);
    void executeCurrent();

    MainWindow* mainWindow_ = nullptr;
    ghidra::ProgramDB* program_ = nullptr;

    QLineEdit* searchEdit_ = nullptr;
    QListWidget* resultList_ = nullptr;
    QLabel* tipLabel_ = nullptr;

    std::vector<PaletteItem> allItems_;
    std::vector<PaletteItem> filteredItems_;
};
