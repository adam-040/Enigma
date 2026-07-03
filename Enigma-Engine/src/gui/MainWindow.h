#pragma once

#include <QMainWindow>
#include <QDockWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QLabel>
#include <QStatusBar>
#include <QMenuBar>
#include <QAction>
#include <QStack>
#include <QFutureWatcher>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include <utility>
#include <vector>

#include <ghidra/storage/EventLog.h>

class SelectionManager;

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

    // Isolation: set via NAV_SKIP env var (bitmask)
    enum NavSkipFlag {
        NavSkip_None           = 0,
        NavSkip_Disasm         = 1 << 0,
        NavSkip_Decompile      = 1 << 1,
        NavSkip_Hex            = 1 << 2,
        NavSkip_FunctionLookup = 1 << 3,
    };
    int navSkipFlags_ = NavSkip_None;
    void setNavSkip(int flags) { navSkipFlags_ = flags; }

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
    void onAddressCursorSync(uint64_t addr);

    // Edit / Undo-Redo
    void onUndo();
    void onRedo();
    void onRenameFunction();
    void onDeleteFunction();
    void onAddLabel();
    void onRemoveLabel();
    void onSetComment();
    void onRemoveComment();
    void onAddBookmark();
    void onDeleteBookmark();

    // Repository
    void onCommit();
    void onCommitHistory();
    void onCreateBranch();
    void onSwitchBranch();

private:
    void createMenuBar();
    void createDockWidgets();
    void createStatusBar();
    void navigateTo(uint64_t addr, const QString& name);
    void populateExplorer();
    void runAnalysisAsync();
    void logOnce(const QString& msg);

    void executeWithEvent(std::unique_ptr<ghidra::storage::Event> event);
    void updateUndoRedoActions();

    std::unique_ptr<ghidra::ProgramDB> program_;
    std::unique_ptr<ghidra::DecompInterface> decompInterface_;
    std::unique_ptr<ghidra::AutoAnalysisManager> analysisMgr_;
    ghidra::storage::EventLog eventLog_;

    ghidra::Function* currentFunction_ = nullptr;
    uint64_t currentAddr_ = 0;
    QStack<uint64_t> backStack_;
    QStack<uint64_t> forwardStack_;
    struct DecompCacheEntry {
        QString cCode;
        QString markupXml;
        std::vector<std::pair<uint64_t, uint64_t>> opAddresses;
    };
    std::unordered_map<uint64_t, DecompCacheEntry> decompCache_;
    QFutureWatcher<void> analysisWatcher_;
    QString lastConsoleMsg_;
    QString currentBinaryPath_;
    std::string repoPath_;
    std::string binaryLanguageId_;
    std::string binaryCompilerSpecId_;
    uint64_t binaryImageBase_ = 0;

    QAction* undoAction_ = nullptr;
    QAction* redoAction_ = nullptr;

    FunctionExplorer* explorer_;
    DisassemblyFieldView* disasmView_;
    DecompilerView* decompView_;
    HexView* hexView_;
    ConsoleWidget* console_;
    QDockWidget* explorerDock_;
    QDockWidget* disasmDock_;
    QDockWidget* decompDock_;
    QDockWidget* hexDock_;
    QDockWidget* consoleDock_;
    QLabel* statusFunc_;
    QLabel* statusAddr_;
    QLabel* statusCount_;
    QAction* showBytesAction_;
    SelectionManager* selectionMgr_ = nullptr;
};
