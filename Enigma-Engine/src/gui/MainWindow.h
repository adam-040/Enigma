#pragma once

#include <QMainWindow>
#include <QTreeWidget>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QLabel>
#include <QStatusBar>
#include <DockManager.h>
#include <QMenuBar>
#include <QAction>
#include <QStack>
#include <QFutureWatcher>
#include <unordered_map>
#include <memory>
#include <cstdint>

namespace ghidra {
class ProgramDB;
class DecompInterface;
class Function;
class AutoAnalysisManager;
}

class FunctionExplorer;
class DisassemblyFieldView;
class DecompilerView;
class HexView;
class ConsoleWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

public:
    void loadBinary(const QString& path);

private slots:
    void onOpenBinary();
    void onSaveProject();
    void onOpenProject();
    void onFunctionSelected(uint64_t addr, const QString& name);
    void onNavigateBack();
    void onNavigateForward();
    void onAnalysisFinished();
    void onDisasmAddressDoubleClicked(uint64_t addr);
    void onDecompAddressDoubleClicked(uint64_t addr);
    void onToggleShowBytes(bool show);

private:
    void createMenuBar();
    void createDockWidgets();
    void createStatusBar();
    void navigateTo(uint64_t addr, const QString& name);
    void populateExplorer();
    void runAnalysisAsync();
    void logOnce(const QString& msg);

    std::unique_ptr<ghidra::ProgramDB> program_;
    std::unique_ptr<ghidra::DecompInterface> decompInterface_;
    std::unique_ptr<ghidra::AutoAnalysisManager> analysisMgr_;

    ghidra::Function* currentFunction_ = nullptr;
    uint64_t currentAddr_ = 0;
    QStack<uint64_t> backStack_;
    QStack<uint64_t> forwardStack_;
    std::unordered_map<uint64_t, QString> decompCache_;
    QFutureWatcher<void> analysisWatcher_;
    QString lastConsoleMsg_;

    FunctionExplorer* explorer_;
    DisassemblyFieldView* disasmView_;
    DecompilerView* decompView_;
    HexView* hexView_;
    ConsoleWidget* console_;
    ads::CDockWidget* explorerDock_;
    ads::CDockWidget* disasmDock_;
    ads::CDockWidget* decompDock_;
    ads::CDockWidget* hexDock_;
    ads::CDockWidget* consoleDock_;
    ads::CDockManager* dockManager_;
    QLabel* statusFunc_;
    QLabel* statusAddr_;
    QLabel* statusCount_;
    QAction* showBytesAction_;
};
