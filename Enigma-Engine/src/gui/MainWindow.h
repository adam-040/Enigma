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
#include <QReadWriteLock>
#include <QTimer>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include <utility>
#include <vector>

#include <ghidra/storage/EventLog.h>
#include <ghidra/storage/FksIndexManager.h>
#include <ghidra/storage/FksRepository.h>

class SelectionManager;

namespace ghidra {
class ProgramDB;
class DecompInterface;
class Function;
class AutoAnalysisManager;
class BinaryLoader;
}

class FunctionExplorer;
class DisassemblyFieldView;
class DecompilerView;
class HexView;
class ConsoleWidget;
class PatchListWidget;
class AddressMinimap;

namespace ghidra::patch { class PatchManager; }

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

    // Patch management
    void onExportPatchedBinary();
    void onShowPatchList();
    void onRevertAllPatches();
    void onSavePatches();
    void onLoadPatches();

    // Repository
    void onCommit();
    void onCommitHistory();
    void onCreateBranch();
    void onSwitchBranch();

    // FKS Index
    void onClearIndex();
    void onAutoClearToggled(bool checked);

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
    void updateTrampolineMap();

    std::unique_ptr<ghidra::ProgramDB> program_;
    std::unique_ptr<ghidra::DecompInterface> decompInterface_;
    std::unique_ptr<ghidra::AutoAnalysisManager> analysisMgr_;
    std::unique_ptr<ghidra::patch::PatchManager> patchManager_;
    std::unique_ptr<ghidra::BinaryLoader> binaryLoader_;
    ghidra::storage::EventLog eventLog_;

    ghidra::Function* currentFunction_ = nullptr;
    int currentFuncVersion_ = -1;  // programVersion_ when currentFunction_ was set
    uint64_t currentAddr_ = 0;
    int programVersion_ = 0;       // bumped on each loadBinary for stale-pointer detection
    QStack<uint64_t> backStack_;
    QStack<uint64_t> forwardStack_;
    struct DecompCacheEntry {
        QString cCode;
        QString markupXml;
        std::vector<std::pair<uint64_t, uint64_t>> opAddresses;
    };
    std::unordered_map<uint64_t, DecompCacheEntry> decompCache_;
    static constexpr size_t kMaxDecompCache = 100;
    void evictDecompCache();

    QFutureWatcher<void> analysisWatcher_;
    QReadWriteLock programLock_;
    bool navBusy_ = false;        // blocking re-entrancy guard for navigateTo
    QString lastConsoleMsg_;
    QString currentBinaryPath_;
    std::string repoPath_;
    std::string binaryLanguageId_;
    std::string binaryCompilerSpecId_;
    uint64_t binaryImageBase_ = 0;

    QAction* undoAction_ = nullptr;
    QAction* redoAction_ = nullptr;
    QAction* showPatchListAction_ = nullptr;

    FunctionExplorer* explorer_;
    DisassemblyFieldView* disasmView_;
    DecompilerView* decompView_;
    HexView* hexView_;
    ConsoleWidget* console_;
    PatchListWidget* patchList_ = nullptr;
    QDockWidget* explorerDock_;
    QDockWidget* disasmDock_;
    QDockWidget* decompDock_;
    QDockWidget* hexDock_;
    QDockWidget* consoleDock_;
    QDockWidget* patchListDock_ = nullptr;
    QLabel* statusFunc_;
    QLabel* statusAddr_;
    QLabel* statusCount_;
    QLabel* hexInfoLabel_;
    QAction* showBytesAction_;
    SelectionManager* selectionMgr_ = nullptr;
    bool autoClearIndex_ = false;
    QTimer* navTimer_ = nullptr;
    uint64_t pendingNavAddr_ = 0;
    QString pendingNavName_;

    void doNavigate(uint64_t addr, const QString& name);
    bool isCurrentFunctionValid() const;
    void updateMinimapViewport();
    AddressMinimap* addressMinimap_ = nullptr;
};
