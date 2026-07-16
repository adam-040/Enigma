#include "MainWindow.h"
#include "FunctionExplorer.h"
#include "DisassemblyFieldView.h"
#include "DecompilerView.h"
#include "HexView.h"
#include "ConsoleWidget.h"
#include "SelectionManager.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QApplication>
#include <QFileInfo>
#include <QtConcurrent>
#include <ghidra/DecompInterface.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/BinaryLoader.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Memory.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/Disassembler.h>
#include <sstream>
#include <iomanip>
#include <windows.h>   // GetCurrentThreadId
#include <chrono>       // timestamps
#include <QInputDialog>
#include <QDir>
#include <ghidra/storage/Repository.h>
#include <ghidra/patch/PatchManager.h>
#include <ghidra/patch/BytePatch.h>
#include <ghidra/patch/NopFillPatch.h>
#include <ghidra/patch/StringPatch.h>
#include <ghidra/patch/MetadataPatch.h>
#include <ghidra/BinaryLoader.h>
#include <ghidra/storage/WorkingSnapshot.h>
#include <ghidra/storage/BranchManager.h>
#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/IndexManager.h>

// Try to find a writable FKS directory.  Checks ENIGMA_FKS_DIR env var first,
// then looks for a writable `fid/index/lmdb/data.mdb` relative to the exe.
static std::string resolveFksDir() {
    // 1. Env var
    std::string dir = ghidra::storage::FksRepository::getFksDirFromEnv();
    if (!dir.empty()) {
        std::string idxDir = ghidra::storage::FksRepository::getIndexDir(dir);
        if (!idxDir.empty()) {
            std::error_code ec;
            if (std::filesystem::exists(idxDir, ec)) return dir;
        }
    }
    // 2. Relative to the executable
    QString exeDir = QCoreApplication::applicationDirPath();
    // Walk up the tree looking for a sibling `fid` directory
    QDir d(exeDir);
    for (int i = 0; i < 8; ++i) {
        QString candidate = d.absolutePath() + "/fid";
        std::error_code ec;
        if (std::filesystem::exists(candidate.toStdString() + "/index/lmdb", ec))
            return candidate.toStdString();
        if (!d.cdUp()) break;
    }
    return "";
}


MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setAnimated(false);
    setCentralWidget(new QWidget(this));

    setStyleSheet(
        "QMainWindow {"
        "    background-color: #f0f0f0;"
        "}"
        "QMainWindow::separator {"
        "    background-color: #d0d0d0;"
        "    width: 1px;"
        "    height: 1px;"
        "    margin: 0px;"
        "    padding: 0px;"
        "}"
        "QDockWidget {"
        "    border: none;"
        "    background-color: #ffffff;"
        "}"
        "QTreeView, QHeaderView, QAbstractScrollArea, QTabWidget::pane, QTabBar {"
        "    border: none;"
        "}"
        "QStatusBar {"
        "    background-color: #f0f0f0;"
        "    border-top: 1px solid #d0d0d0;"
        "}"
        "QStatusBar::item {"
        "    border: none;"
        "}"
        "QStatusBar QLabel {"
        "    color: #404040;"
        "    font-size: 11px;"
        "    padding: 2px 5px;"
        "}"
    );

    createDockWidgets();
    createMenuBar();
    createStatusBar();

    decompInterface_ = std::make_unique<ghidra::DecompInterface>();
    patchManager_ = std::make_unique<ghidra::patch::PatchManager>();
    navTimer_ = new QTimer(this);
    navTimer_->setSingleShot(true);
    navTimer_->setInterval(80);
    connect(navTimer_, &QTimer::timeout, this, [this]() {
        if (pendingNavAddr_ != 0) {
            doNavigate(pendingNavAddr_, pendingNavName_);
            pendingNavAddr_ = 0;
            pendingNavName_.clear();
        }
    });
}

MainWindow::~MainWindow() = default;

void MainWindow::createMenuBar() {
    auto* file = menuBar()->addMenu(tr("&File"));
    auto* openBin = file->addAction(tr("&Open Binary..."));
    openBin->setShortcut(QKeySequence::Open);
    connect(openBin, &QAction::triggered, this, &MainWindow::onOpenBinary);

    auto* save = file->addAction(tr("&Save Project"));
    save->setShortcut(QKeySequence::Save);
    connect(save, &QAction::triggered, this, &MainWindow::onSaveProject);

    auto* openProj = file->addAction(tr("Open &Project..."));
    connect(openProj, &QAction::triggered, this, &MainWindow::onOpenProject);

    file->addSeparator();
    auto* quit = file->addAction(tr("&Quit"));
    quit->setShortcut(QKeySequence::Quit);
    connect(quit, &QAction::triggered, qApp, &QApplication::quit);

    auto* edit = menuBar()->addMenu(tr("&Edit"));
    auto* undoAct = edit->addAction(tr("&Undo"));
    undoAct->setShortcut(QKeySequence::Undo);
    connect(undoAct, &QAction::triggered, this, &MainWindow::onUndo);
    auto* redoAct = edit->addAction(tr("&Redo"));
    redoAct->setShortcut(QKeySequence::Redo);
    connect(redoAct, &QAction::triggered, this, &MainWindow::onRedo);

    edit->addSeparator();
    auto* renameFuncAct = edit->addAction(tr("Rename &Function"));
    renameFuncAct->setShortcut(QKeySequence(Qt::Key_N));
    connect(renameFuncAct, &QAction::triggered, this, &MainWindow::onRenameFunction);
    auto* deleteFuncAct = edit->addAction(tr("&Delete Function"));
    deleteFuncAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_Delete));
    connect(deleteFuncAct, &QAction::triggered, this, &MainWindow::onDeleteFunction);

    edit->addSeparator();
    auto* addLabelAct = edit->addAction(tr("Add &Label..."));
    addLabelAct->setShortcut(QKeySequence(Qt::Key_L));
    connect(addLabelAct, &QAction::triggered, this, &MainWindow::onAddLabel);
    auto* removeLabelAct = edit->addAction(tr("&Remove Label..."));
    removeLabelAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_L));
    connect(removeLabelAct, &QAction::triggered, this, &MainWindow::onRemoveLabel);

    edit->addSeparator();
    auto* setCommentAct = edit->addAction(tr("Set Co&mment..."));
    setCommentAct->setShortcut(QKeySequence(Qt::Key_Semicolon));
    connect(setCommentAct, &QAction::triggered, this, &MainWindow::onSetComment);
    auto* removeCommentAct = edit->addAction(tr("&Remove Comment..."));
    connect(removeCommentAct, &QAction::triggered, this, &MainWindow::onRemoveComment);

    edit->addSeparator();
    auto* addBmAct = edit->addAction(tr("Add &Bookmark..."));
    addBmAct->setShortcut(QKeySequence(Qt::Key_B));
    connect(addBmAct, &QAction::triggered, this, &MainWindow::onAddBookmark);
    auto* deleteBmAct = edit->addAction(tr("Delete B&ookmark..."));
    connect(deleteBmAct, &QAction::triggered, this, &MainWindow::onDeleteBookmark);

    auto* view = menuBar()->addMenu(tr("&View"));

    auto* disasmAct = disasmDock_->toggleViewAction();
    disasmAct->setText(tr("&Disassembly"));
    view->addAction(disasmAct);

    auto* decompAct = decompDock_->toggleViewAction();
    decompAct->setText(tr("&Decompiler"));
    view->addAction(decompAct);

    auto* hexAct = hexDock_->toggleViewAction();
    hexAct->setText(tr("&Hex"));
    view->addAction(hexAct);

    auto* consoleAct = consoleDock_->toggleViewAction();
    consoleAct->setText(tr("&Console"));
    view->addAction(consoleAct);

    view->addSeparator();
    showBytesAction_ = view->addAction(tr("Show &Bytes"));
    showBytesAction_->setCheckable(true);
    showBytesAction_->setChecked(true);
    connect(showBytesAction_, &QAction::toggled, this, &MainWindow::onToggleShowBytes);

    auto* navigate = menuBar()->addMenu(tr("&Navigate"));
    auto* back = navigate->addAction(tr("&Back"));
    back->setShortcut(QKeySequence::Back);
    connect(back, &QAction::triggered, this, &MainWindow::onNavigateBack);

    auto* fwd = navigate->addAction(tr("&Forward"));
    fwd->setShortcut(QKeySequence::Forward);
    connect(fwd, &QAction::triggered, this, &MainWindow::onNavigateForward);

    auto* analysis = menuBar()->addMenu(tr("&Analysis"));
    auto* analyzeAct = analysis->addAction(tr("&Auto Analyze"));
    connect(analyzeAct, &QAction::triggered, this, [this]() {
        if (program_) runAnalysisAsync();
    });

    auto* repo = menuBar()->addMenu(tr("&Repository"));
    auto* commitAct = repo->addAction(tr("&Commit..."));
    commitAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_K));
    connect(commitAct, &QAction::triggered, this, &MainWindow::onCommit);

    auto* historyAct = repo->addAction(tr("Commit &History..."));
    connect(historyAct, &QAction::triggered, this, &MainWindow::onCommitHistory);

    repo->addSeparator();

    auto* createBranchAct = repo->addAction(tr("Create &Branch..."));
    connect(createBranchAct, &QAction::triggered, this, &MainWindow::onCreateBranch);

    auto* switchBranchAct = repo->addAction(tr("&Switch Branch..."));
    connect(switchBranchAct, &QAction::triggered, this, &MainWindow::onSwitchBranch);

    auto* tools = menuBar()->addMenu(tr("&Tools"));
    auto* autoClearAct = tools->addAction(tr("Auto Clear Index"));
    autoClearAct->setCheckable(true);
    autoClearAct->setChecked(autoClearIndex_);
    connect(autoClearAct, &QAction::toggled, this, &MainWindow::onAutoClearToggled);

    auto* clearNowAct = tools->addAction(tr("Clear Index Now"));
    connect(clearNowAct, &QAction::triggered, this, &MainWindow::onClearIndex);

    auto* patchMenu = menuBar()->addMenu(tr("&Patch"));
    auto* exportAct = patchMenu->addAction(tr("&Export Patched Binary..."));
    connect(exportAct, &QAction::triggered, this, &MainWindow::onExportPatchedBinary);

    auto* listAct = patchMenu->addAction(tr("&Show Patch List..."));
    connect(listAct, &QAction::triggered, this, &MainWindow::onShowPatchList);

    auto* revertAllAct = patchMenu->addAction(tr("&Revert All Patches"));
    connect(revertAllAct, &QAction::triggered, this, &MainWindow::onRevertAllPatches);

    menuBar()->addMenu(tr("&Help"));
}

void MainWindow::createDockWidgets() {
    disasmView_ = new DisassemblyFieldView(this);
    disasmView_->setShowBytes(true);
    decompView_ = new DecompilerView(this);
    hexView_ = new HexView(this);
    console_ = new ConsoleWidget(this);
    explorer_ = new FunctionExplorer(this);

    auto createDock = [&](const QString& title, QWidget* widget, bool closable = true) -> QDockWidget* {
        auto* dock = new QDockWidget(title, this);
        dock->setObjectName(title);
        dock->setWidget(widget);
        if (closable) {
            dock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetClosable);
        } else {
            dock->setFeatures(QDockWidget::DockWidgetMovable);
        }
        return dock;
    };

    explorerDock_ = createDock("EXPLORER", explorer_, false);
    disasmDock_   = createDock("DISASSEMBLY", disasmView_);
    decompDock_   = createDock("DECOMPILER", decompView_);
    hexDock_      = createDock("HEX", hexView_);
    consoleDock_  = createDock("CONSOLE", console_);

    setDockNestingEnabled(true);
    if (centralWidget()) {
        centralWidget()->hide();
    }

    addDockWidget(Qt::LeftDockWidgetArea, explorerDock_);
    addDockWidget(Qt::RightDockWidgetArea, disasmDock_);

    splitDockWidget(disasmDock_, decompDock_, Qt::Horizontal);
    splitDockWidget(disasmDock_, consoleDock_, Qt::Vertical);
    splitDockWidget(decompDock_, hexDock_, Qt::Vertical);

    connect(explorer_, &FunctionExplorer::functionSelected,
            this, &MainWindow::onFunctionSelected);
    connect(explorer_->autoClearCheckbox(), &QCheckBox::toggled,
            this, &MainWindow::onAutoClearToggled);
    connect(explorer_->clearIndexButton(), &QPushButton::clicked,
            this, &MainWindow::onClearIndex);
    connect(disasmView_, &DisassemblyFieldView::seekRequested,
            this, &MainWindow::onDisasmAddressDoubleClicked);
    connect(decompView_, &DecompilerView::seekRequested,
            this, &MainWindow::onDecompAddressDoubleClicked);

    // --- Sync navigation: cursor movement in any FieldView syncs the others ---
    selectionMgr_ = new SelectionManager(this);
    disasmView_->setSelectionManager(selectionMgr_);
    decompView_->setSelectionManager(selectionMgr_);
    hexView_->setSelectionManager(selectionMgr_);

    connect(disasmView_, &DisassemblyFieldView::cursorAddressChanged,
            this, &MainWindow::onAddressCursorSync);
    connect(hexView_, &HexView::cursorAddressChanged,
            this, &MainWindow::onAddressCursorSync);
    connect(hexView_, &HexView::patchByteRequested, this, [this](uint64_t addr) {
        if (!patchManager_ || !program_) return;
        bool ok = false;
        QString input = QInputDialog::getText(this, tr("Patch Byte"),
            tr("New hex value at 0x%1:").arg(addr, 0, 16),
            QLineEdit::Normal, QString(), &ok);
        if (!ok) return;
        uint32_t val = input.toUInt(&ok, 16);
        if (!ok || val > 255) return;
        std::vector<uint8_t> oldBytes(1), newBytes(1);
        auto* mem = program_->getMemory();
        if (mem) {
            auto af = program_->getAddressFactory();
            auto address = af->oldGetAddressFromLong(addr);
            oldBytes[0] = mem->getByte(address);
        }
        newBytes[0] = static_cast<uint8_t>(val);
        auto patch = std::make_unique<ghidra::patch::BytePatch>(
            addr, oldBytes, newBytes, "");
        patchManager_->addPatch(std::move(patch));
        console_->log(QString("Patched byte @ 0x%1: -> 0x%2")
            .arg(addr, 0, 16).arg(val, 2, 16, QChar('0')));
    });
    connect(hexView_, &HexView::patchNopFillRequested, this, [this](uint64_t start, uint64_t end) {
        if (!patchManager_ || !program_ || end <= start) return;
        uint64_t size = end - start + 1;
        auto patch = std::make_unique<ghidra::patch::NopFillPatch>(start, size, 0x90, "");
        patchManager_->addPatch(std::move(patch));
        console_->log(QString("NOP-filled 0x%1 bytes @ 0x%2").arg(size).arg(start, 0, 16));
    });
    connect(hexView_, &HexView::patchStringRequested, this, [this](uint64_t addr) {
        if (!patchManager_ || !program_) return;
        bool ok = false;
        QString newStr = QInputDialog::getText(this, tr("Patch String"),
            tr("New string at 0x%1:").arg(addr, 0, 16),
            QLineEdit::Normal, QString(), &ok);
        if (!ok) return;
        auto patch = std::make_unique<ghidra::patch::StringPatch>(
            addr, newStr.toStdString(), "");
        patchManager_->addPatch(std::move(patch));
        console_->log(QString("Patched string @ 0x%1: \"%2\"").arg(addr, 0, 16).arg(newStr));
    });
    connect(decompView_, &DecompilerView::cursorAddressChanged,
            this, &MainWindow::onAddressCursorSync);
}



void MainWindow::createStatusBar() {
    auto* sb = statusBar();
    statusFunc_ = new QLabel(tr("No binary loaded"));
    statusAddr_ = new QLabel(QString());
    statusCount_ = new QLabel(QString());

    sb->addWidget(statusFunc_, 1);
    sb->addWidget(statusAddr_);
    sb->addPermanentWidget(statusCount_);
}

static FILE* g_log = nullptr;
static long long g_t0 = 0;
static long long nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
static FILE* logFile() {
    if (!g_log) {
        g_t0 = nowMs();
        const char* envPath = getenv("DBG_LOG");
        const char* path = envPath ? envPath : "C:\\Users\\pc\\Desktop\\enigma_gui_debug.log";
        g_log = fopen(path, "w");
    }
    return g_log;
}
#define DBG(...) do { FILE* _dbf = logFile(); if(_dbf){fprintf(_dbf, "[%+6lld|%04lu] ", nowMs()-g_t0, (unsigned long)GetCurrentThreadId());fprintf(_dbf, __VA_ARGS__);fflush(_dbf);} } while(0)
#define NAVLOG(...) DBG("[NAV] " __VA_ARGS__)
#define GUARD_ENTER(fn) DBG(">> %s\n", fn)
#define GUARD_EXIT(fn)  DBG("<< %s\n", fn)
#define GUARD_EXIT_IF(cond, fn, reason) do { if (cond) { DBG("<< %s EARLY: %s\n", fn, reason); return; } } while(0)

void MainWindow::onOpenBinary() {
    QString path = QFileDialog::getOpenFileName(this, tr("Open Binary"),
        QString(), tr("Executables (*.exe *.dll *.elf *.so *.bin);;All Files (*)"));
    if (path.isEmpty()) return;
    DBG("[onOpenBinary] path=%s\n", path.toStdString().c_str());
    loadBinary(path);
}

void MainWindow::onSaveProject() {
    if (!program_) {
        console_->log("No program loaded to save.");
        return;
    }
    QString dir = QFileDialog::getExistingDirectory(this, tr("Save Project To"));
    if (dir.isEmpty()) return;

    std::string repoDir = dir.toStdString();

    // Create repo if it doesn't exist yet, otherwise just open/verify
    bool repoReady = ghidra::storage::Repository::open(repoDir);
    if (!repoReady) {
        repoReady = ghidra::storage::Repository::create(
            repoDir,
            program_->getName(),
            currentBinaryPath_.toStdString(),
            "",
            binaryLanguageId_,
            binaryCompilerSpecId_,
            binaryImageBase_);
    }
    if (!repoReady) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to create/open repository at:\n") + dir);
        return;
    }

    std::string snapPath = ghidra::storage::Repository::getWorkingSnapshotPath(repoDir);
    if (!ghidra::storage::WorkingSnapshot::save(*program_, snapPath)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to save working snapshot."));
        return;
    }

    repoPath_ = repoDir;
    setWindowTitle(tr("Enigma Engine \u2014 %1 [%2]")
        .arg(QString::fromStdString(program_->getName()))
        .arg(dir));
    console_->log("Project saved to: " + dir);
}

void MainWindow::onOpenProject() {
    QString dir = QFileDialog::getExistingDirectory(this, tr("Open Project"));
    if (dir.isEmpty()) return;

    std::string repoDir = dir.toStdString();
    if (!ghidra::storage::Repository::open(repoDir)) {
        QMessageBox::warning(this, tr("Error"),
            tr("Not a valid Enigma project directory:\n") + dir);
        return;
    }

    std::string snapPath = ghidra::storage::Repository::getWorkingSnapshotPath(repoDir);
    auto prog = ghidra::storage::WorkingSnapshot::load(snapPath);
    if (!prog) {
        QMessageBox::warning(this, tr("Error"),
            tr("Failed to load project snapshot from:\n") + dir);
        return;
    }

    // Stop any running analysis
    if (analysisWatcher_.isRunning()) analysisWatcher_.waitForFinished();
    analysisMgr_.reset();
    decompCache_.clear();
    backStack_.clear();
    forwardStack_.clear();
    currentFunction_ = nullptr;
    currentAddr_ = 0;
    eventLog_.clear();

    // Swap program
    decompInterface_->closeProgram();
    program_.reset(prog.release());

    if (!decompInterface_->openProgram(program_.get())) {
        QMessageBox::warning(this, tr("Error"),
            tr("Failed to open program in decompiler."));
        program_.reset();
        return;
    }

    disasmView_->setProgram(program_.get());
    disasmView_->setDecompInterface(decompInterface_.get());
    repoPath_ = repoDir;

    populateExplorer();
    runAnalysisAsync();

    setWindowTitle(tr("Enigma Engine \u2014 %1 [%2]")
        .arg(QString::fromStdString(program_->getName()))
        .arg(dir));
    console_->log("Project loaded from: " + dir);
}

void MainWindow::loadBinary(const QString& path) {
    GUARD_ENTER("loadBinary");
    NAVLOG("path='%s'\n", path.toStdString().c_str());
    console_->log("> Loading: " + path);
    currentBinaryPath_ = path;
    QApplication::processEvents();

    try {
    auto loader = ghidra::createLoader();
    if (!loader) { NAVLOG("createLoader returned null\n"); GUARD_EXIT("loadBinary"); return; }
    NAVLOG("createLoader OK\n");

    if (!loader->load(path.toStdString())) {
        NAVLOG("loader->load failed\n");
        QMessageBox::warning(this, tr("Error"),
            tr("Failed to load binary:\n") + path);
        console_->log("Failed to load binary.");
        return;
    }
    DBG("[loadBinary] loader->load OK, format=%s arch=%s bit=%d endian=%d binary=%s\n",
        loader->getFormatName().c_str(), loader->getArchitecture().c_str(),
        loader->getBitness(), loader->isBigEndian(),
        path.toStdString().c_str());

    QFileInfo fi(path);
    auto* prog = new ghidra::ProgramDB(fi.fileName().toStdString(), nullptr, nullptr);
    DBG("[loadBinary] ProgramDB constructed\n");

    if (!prog->getMemory()) {
        DBG("[loadBinary] getMemory returned null\n");
        QMessageBox::warning(this, tr("Error"),
            tr("ProgramDB initialization failed (null Memory)."));
        delete prog;
        console_->log("ProgramDB: getMemory() returned null after init.");
        return;
    }
    DBG("[loadBinary] getMemory OK\n");

    auto* addrFactory = dynamic_cast<ghidra::ProgramAddressFactory*>(prog->getAddressFactory());
    if (!addrFactory) {
        DBG("[loadBinary] dynamic_cast<ProgramAddressFactory> failed\n");
        QMessageBox::warning(this, tr("Error"),
            tr("ProgramDB has no address factory."));
        delete prog;
        console_->log("ProgramDB: getAddressFactory() returned null or wrong type.");
        return;
    }
    DBG("[loadBinary] addrFactory OK\n");

    auto* ramSpace = new ghidra::GenericAddressSpace("ram", 64,
        ghidra::AddressSpace::TYPE_RAM, 1);
    auto* constSpace = new ghidra::GenericAddressSpace("const", 64,
        ghidra::AddressSpace::TYPE_CONSTANT, 2);
    auto* uniqueSpace = new ghidra::GenericAddressSpace("unique", 64,
        ghidra::AddressSpace::TYPE_UNIQUE, 3);
    auto* regSpace = new ghidra::GenericAddressSpace("register", 64,
        ghidra::AddressSpace::TYPE_REGISTER, 4);
    auto* stackSpace = new ghidra::GenericAddressSpace("stack", 64,
        ghidra::AddressSpace::TYPE_STACK, 5);

    addrFactory->addAddressSpace(ramSpace);
    addrFactory->addAddressSpace(constSpace);
    addrFactory->addAddressSpace(uniqueSpace);
    addrFactory->addAddressSpace(regSpace);
    addrFactory->addAddressSpace(stackSpace);
    addrFactory->setDefaultSpace(ramSpace);
    addrFactory->setConstantSpace(ramSpace);
    addrFactory->setUniqueSpace(ramSpace);
    addrFactory->setRegisterSpace(ramSpace);
    addrFactory->setStackSpace(ramSpace);
    DBG("[loadBinary] address spaces registered\n");

    // Log memory block regions before populateProgram
    DBG("[loadBinary] dumping memory state BEFORE populateProgram...\n");
    ghidra::DefaultMemory* memDebug = dynamic_cast<ghidra::DefaultMemory*>(prog->getMemory());
    if (memDebug) {
        auto blocks = memDebug->getBlocks();
        DBG("[loadBinary]   blocks count: %zu\n", blocks.size());
        for (auto* b : blocks) {
            DBG("[loadBinary]   block '%s': 0x%llx - 0x%llx\n",
                b->getName().c_str(),
                b->getStart().getOffset(),
                b->getEnd().getOffset());
        }
    } else {
        DBG("[loadBinary]   memory is not DefaultMemory\n");
    }
    DBG("[loadBinary] entry point = 0x%llx, image base = 0x%llx\n",
        (unsigned long long)loader->getEntryPoint(),
        (unsigned long long)loader->getImageBase());

    // DIAGNOSTIC: dump pre-populate state
    {
        auto* fm = prog->getFunctionManager();
        auto* sym = prog->getSymbolTable();
        auto* dtm = prog->getDataTypeManager();
        auto* listing = prog->getListing();
        DBG("[DIAG] PRE-POPULATE: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
            fm ? fm->getFunctionCount() : -1,
            sym ? sym->getNumSymbols() : -1,
            dtm ? dtm->getDataTypeCount(false) : -1,
            listing ? listing->getDataCount() : 0);
        // First 5 function addresses if any
        if (fm) {
            ghidra::FunctionIterator fit = fm->getFunctions(true);
            int i = 0;
            while (fit.hasNext() && i < 10) {
                auto* f = fit.next();
                if (f) DBG("[DIAG]   fun[%d] = 0x%llx '%s'\n", i,
                    (unsigned long long)f->getEntryPoint().getOffset(), f->getName().c_str());
                i++;
            }
        }
    }

    DBG("[loadBinary] calling populateProgram...\n");
    try {
        if (!loader->populateProgram(prog)) {
            DBG("[loadBinary] populateProgram returned false\n");
            QMessageBox::warning(this, tr("Error"),
                tr("Failed to populate program from:\n") + path);
            delete prog;
            console_->log("populateProgram() returned false.");
            return;
        }
    } catch (const std::exception& e) {
        DBG("[loadBinary] populateProgram threw: %s\n", e.what());
        QMessageBox::warning(this, tr("Error"), tr("populateProgram threw: %1").arg(e.what()));
        delete prog;
        return;
    } catch (...) {
        DBG("[loadBinary] populateProgram threw unknown exception\n");
        QMessageBox::warning(this, tr("Error"), tr("populateProgram threw unknown exception"));
        delete prog;
        return;
    }
    DBG("[loadBinary] populateProgram() succeeded.\n");

    // DIAGNOSTIC: dump post-populate state
    {
        auto* fm = prog->getFunctionManager();
        auto* sym = prog->getSymbolTable();
        auto* dtm = prog->getDataTypeManager();
        auto* listing = prog->getListing();
        DBG("[DIAG] POST-POPULATE: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
            fm ? fm->getFunctionCount() : -1,
            sym ? sym->getNumSymbols() : -1,
            dtm ? dtm->getDataTypeCount(false) : -1,
            listing ? listing->getDataCount() : 0);
        if (fm) {
            ghidra::FunctionIterator fit = fm->getFunctions(true);
            int i = 0;
            while (fit.hasNext() && i < 10) {
                auto* f = fit.next();
                if (f) DBG("[DIAG]   fun[%d] = 0x%llx '%s'\n", i,
                    (unsigned long long)f->getEntryPoint().getOffset(), f->getName().c_str());
                i++;
            }
        }
        if (sym) DBG("[DIAG]   getExternalEntryPoints count = %zu\n", sym->getExternalEntryPoints().size());
        auto* extMgr = prog->getExternalManager();
        if (extMgr) DBG("[DIAG]   extManager externalLocationCount = %d\n", extMgr->getExternalLocationCount());
    }

    // Log memory block regions AFTER populateProgram
    {
        ghidra::DefaultMemory* memDebug2 = dynamic_cast<ghidra::DefaultMemory*>(prog->getMemory());
        if (memDebug2) {
            auto blocks = memDebug2->getBlocks();
            DBG("[loadBinary]   after populate: blocks count: %zu\n", blocks.size());
            for (auto* b : blocks) {
                DBG("[loadBinary]   block '%s': 0x%llx - 0x%llx (size %lld, init=%d)\n",
                    b->getName().c_str(),
                    (unsigned long long)b->getStart().getOffset(),
                    (unsigned long long)b->getEnd().getOffset(),
                    (long long)b->getSize(),
                    b->isInitialized());
            }
        }
    }
    // Log all functions
    if (prog->getFunctionManager()) {
        auto fit = prog->getFunctionManager()->getFunctions(true);
        DBG("[loadBinary] functions after populate:\n");
        while (fit.hasNext()) {
            auto* f = fit.next();
            if (f)
                DBG("[loadBinary]   FUNC 0x%llx '%s'\n", f->getEntryPoint().getOffset(), f->getName().c_str());
        }
    }

    if (analysisWatcher_.isRunning()) {
        DBG("[loadBinary] waiting for previous analysis...\n");
        analysisWatcher_.waitForFinished();
    }

    // Write-lock while replacing program and related state.
    programLock_.lockForWrite();
    analysisMgr_.reset();
    decompCache_.clear();
    backStack_.clear();
    forwardStack_.clear();
    currentFunction_ = nullptr;
    currentAddr_ = 0;
    ++programVersion_;

    // Release PatchMemory ownership from PatchManager *before* destroying old program,
    // because the old program owns PatchMemory via memory_.reset(patchMemory_.get())
    // in installPatchMemory. Without this, the old program's destructor deletes PatchMemory
    // while PatchManager's unique_ptr still points to it → double-free → crash on second load.
    patchManager_->releasePatchMemory();
    program_.reset(prog);
    DBG("[loadBinary] installing PatchMemory...\n");
    patchManager_->setProgram(program_.get());
    patchManager_->setBinaryLoader(loader.get());
    patchManager_->installPatchMemory(program_.get());
    patchManager_->patchMemory()->setOnBytesChanged(
        [this](uint64_t, uint64_t) {
            if (hexView_ && hexView_->isVisible())
                hexView_->viewport()->update();
        });
    hexView_->setPatchMemory(patchManager_->patchMemory());
    DBG("[loadBinary] calling decompInterface_->closeProgram...\n");
    decompInterface_->closeProgram();
    // Update view pointers to new program immediately (before any failure that could return).
    disasmView_->setProgram(program_.get());
    disasmView_->setDecompInterface(decompInterface_.get());
    // Log address factory details
    {
        auto* af = prog->getAddressFactory();
        if (af) {
            auto spaces = af->getAddressSpaces();
            for (auto* sp : spaces) {
                DBG("[loadBinary]   address space: '%s' type=%d default=%s\n",
                    sp->getName().c_str(),
                    sp->getType(),
                    (sp == af->getDefaultAddressSpace()) ? "YES" : "no");
            }
            DBG("[loadBinary]   defaultSpace = '%s'\n",
                af->getDefaultAddressSpace() ? af->getDefaultAddressSpace()->getName().c_str() : "(null)");
        }
    }

    DBG("[loadBinary] calling decompInterface_->openProgram...\n");
    bool openOk = false;
    try {
        openOk = decompInterface_->openProgram(prog);
    } catch (const std::exception& e) {
        DBG("[loadBinary] openProgram threw: %s\n", e.what());
        console_->log(QString("openProgram threw: %1").arg(e.what()));
    } catch (...) {
        DBG("[loadBinary] openProgram threw unknown\n");
        console_->log("openProgram threw unknown exception");
    }
    if (!openOk) {
        DBG("[loadBinary] openProgram returned false\n");
        QMessageBox::warning(this, tr("Error"), tr("Failed to open program in decompiler."));
        programLock_.unlock();
        console_->log("Failed to open program in decompiler (architecture may not be supported).");
        return;
    }
    DBG("[loadBinary] openProgram succeeded\n");
    programLock_.unlock();

    // decompInterface_ internally holds prog after openProgram call

    // DIAGNOSTIC: dump state before populateExplorer
    {
        auto* fm = prog->getFunctionManager();
        auto* sym = prog->getSymbolTable();
        auto* dtm = prog->getDataTypeManager();
        auto* listing = prog->getListing();
        DBG("[DIAG] PRE-EXPLORER: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
            fm ? fm->getFunctionCount() : -1,
            sym ? sym->getNumSymbols() : -1,
            dtm ? dtm->getDataTypeCount(false) : -1,
            listing ? listing->getDataCount() : 0);
    }

    QString binaryName = QFileInfo(path).fileName();
    setWindowTitle(tr("Enigma Engine — %1").arg(binaryName));

    NAVLOG("calling populateExplorer...\n");
    try {
        populateExplorer();
    } catch (const std::exception& e) {
        NAVLOG("populateExplorer THREW: %s - CAUGHT (no crash)\n", e.what());
        console_->log(QString("populateExplorer error: %1").arg(e.what()));
    } catch (...) {
        NAVLOG("populateExplorer THREW unknown - CAUGHT (no crash)\n");
        console_->log("populateExplorer unknown error");
    }
    NAVLOG("populateExplorer done\n");

    // Auto-clear FKS index before analysis if enabled
    if (autoClearIndex_) {
        console_->log("> Auto-clearing FKS index...");
        QApplication::processEvents();
        std::string fksDir = resolveFksDir();
        if (!fksDir.empty()) {
            console_->log(QString("  FKS dir: %1").arg(QString::fromStdString(fksDir)));
            std::string error;
            if (ghidra::storage::FksIndexManager::clear(fksDir, &error)) {
                console_->log("  FKS index cleared.");
            } else {
                console_->log("  Failed to clear FKS index.");
                if (!error.empty())
                    console_->log(QString("  Error: %1").arg(QString::fromStdString(error)));
            }
        } else {
            console_->log("  No writable FKS index found; skipping clear.");
        }
    }

    console_->log(QString("Binary loaded: %1").arg(binaryName));
    console_->log(QString("Architecture: %1-bit %2%3")
        .arg(loader->getBitness())
        .arg(loader->getArchitecture().c_str())
        .arg(loader->isBigEndian() ? " BE" : " LE"));

    NAVLOG("calling runAnalysisAsync...\n");
    runAnalysisAsync();
    } catch (const std::exception& e) {
        NAVLOG("loadBinary UNHANDLED EXCEPTION: %s\n", e.what());
        console_->log(QString("FATAL: loadBinary threw: %1").arg(e.what()));
        QMessageBox::critical(this, tr("Error"),
            tr("An unexpected error occurred while loading the binary:\n%1").arg(e.what()));
    } catch (...) {
        NAVLOG("loadBinary UNHANDLED EXCEPTION: unknown\n");
        console_->log("FATAL: loadBinary threw unknown exception");
        QMessageBox::critical(this, tr("Error"),
            tr("An unexpected error occurred while loading the binary."));
    }
    GUARD_EXIT("loadBinary");
}

bool MainWindow::isCurrentFunctionValid() const {
    return currentFunction_ != nullptr && currentFuncVersion_ == programVersion_;
}

void MainWindow::evictDecompCache() {
    if (decompCache_.size() <= kMaxDecompCache) return;
    // Evict oldest entries (unordered_map has no order, so just clear all)
    decompCache_.clear();
}

void MainWindow::populateExplorer() {
    GUARD_ENTER("populateExplorer");
    NAVLOG("program_=%p\n", (void*)program_.get());
    explorer_->clear();
    if (!program_) { NAVLOG("abort: program_ null\n"); GUARD_EXIT("populateExplorer"); return; }

    {
        auto* fm = program_->getFunctionManager();
        auto* sym = program_->getSymbolTable();
        auto* listing = program_->getListing();
        NAVLOG("funcCount=%d symCount=%d dataCount=%zu\n",
            fm ? fm->getFunctionCount() : -1,
            sym ? sym->getNumSymbols() : -1,
            listing ? listing->getDataCount() : 0);
    }

    QTreeWidgetItem* root = explorer_->addCategory("Functions");
    NAVLOG("getting function list from decompInterface...\n");
    auto funcs = decompInterface_->getFunctions();
    NAVLOG("got %zu functions\n", funcs.size());
    explorer_->treeWidget()->setUpdatesEnabled(false);
    explorer_->treeWidget()->setSortingEnabled(false);
    for (auto& f : funcs) {
        uint64_t addr = f.entryAddress.getOffset();
        explorer_->addEntry(root, addr, QString::fromStdString(f.name));
    }
    explorer_->treeWidget()->setSortingEnabled(true);
    explorer_->treeWidget()->setUpdatesEnabled(true);

    QString binaryName = QString::fromStdString(program_->getName());
    if (binaryName.isEmpty()) binaryName = "Program";

    auto* funcMgr = program_->getFunctionManager();
    int fmCount = funcMgr ? funcMgr->getFunctionCount() : -1;
    if (funcMgr) {
        statusCount_->setText(tr("%1 functions").arg(fmCount));
    } else {
        statusCount_->setText(tr("%1 functions").arg(funcs.size()));
    }
    statusFunc_->setText(binaryName);

    // Exports
    auto* symTable = program_->getSymbolTable();
    if (symTable) {
        auto extPoints = symTable->getExternalEntryPoints();
        if (!extPoints.empty()) {
            QTreeWidgetItem* exportsCat = explorer_->addCategory("Exports");
            for (auto& addr : extPoints) {
                auto syms = symTable->getSymbols(addr);
                QString symName;
                for (auto* s : syms) {
                    if (s) { symName = QString::fromStdString(s->getName()); break; }
                }
                if (symName.isEmpty()) symName = QString("sub_%1").arg(addr.getOffset(), 0, 16);
                explorer_->addEntry(exportsCat, addr.getOffset(), symName);
            }
        }
    }

    // Imports
    auto* extMgr = program_->getExternalManager();
    if (extMgr && extMgr->getExternalLocationCount() > 0) {
        QTreeWidgetItem* importsCat = explorer_->addCategory("Imports");
        auto locations = extMgr->getExternalLocations();
        for (auto* loc : locations) {
            if (!loc) continue;
            explorer_->addEntry(importsCat, loc->getAddress().getOffset(),
                QString::fromStdString(loc->getLabel()));
        }
    }

    // Segments
    auto* mem = program_->getMemory();
    if (mem) {
        auto blocks = mem->getBlocks();
        if (!blocks.empty()) {
            QTreeWidgetItem* segsCat = explorer_->addCategory("Segments");
            for (auto* block : blocks) {
                if (!block) continue;
                explorer_->addEntry(segsCat, block->getStart().getOffset(),
                    QString::fromStdString(block->getName()));
            }
        }
    }
    GUARD_EXIT("populateExplorer");
}

void MainWindow::runAnalysisAsync() {
    GUARD_ENTER("runAnalysisAsync");
    NAVLOG("program_=%p analysisWatcher_.isRunning=%d\n",
        (void*)program_.get(), analysisWatcher_.isRunning());
    if (!program_) { NAVLOG("abort: program_ null\n"); GUARD_EXIT("runAnalysisAsync"); return; }
    if (analysisWatcher_.isRunning()) {
        console_->log("Analysis already in progress.");
        NAVLOG("abort: analysis already running\n");
        GUARD_EXIT("runAnalysisAsync"); return;
    }

    console_->log("> Analysis started...");
    QApplication::processEvents();

    analysisMgr_ = std::make_unique<ghidra::AutoAnalysisManager>(program_.get());
    analysisMgr_->initializeDefaultAnalyzers();
    NAVLOG("analysisMgr_ created=%p\n", (void*)analysisMgr_.get());

    auto future = QtConcurrent::run([this]() {
        DBG("[analysis worker] START (thread)\n");
        // Read-lock the program while analysis runs on the worker thread.
        programLock_.lockForRead();
        NAVLOG("worker: analysisMgr_=%p program_=%p\n",
            (void*)analysisMgr_.get(), (void*)program_.get());
        if (analysisMgr_) {
            NAVLOG("worker: calling analyze()...\n");
            if (program_) {
                auto* fm = program_->getFunctionManager();
                NAVLOG("worker: PRE-ANALYZE funcCount=%d\n",
                    fm ? fm->getFunctionCount() : -1);
            }
            try {
                analysisMgr_->analyze(&ghidra::getDummyMonitor());
                NAVLOG("worker: analyze() completed\n");
                if (program_) {
                    auto* fm = program_->getFunctionManager();
                    NAVLOG("worker: POST-ANALYZE funcCount=%d\n",
                        fm ? fm->getFunctionCount() : -1);
                }
            } catch (const std::exception& e) {
                NAVLOG("worker: analyze() threw: %s\n", e.what());
            } catch (...) {
                NAVLOG("worker: analyze() threw unknown\n");
            }
        }
        programLock_.unlock();
        NAVLOG("worker: END\n");
    });

    analysisWatcher_.setFuture(future);
    // Disconnect any previous connection to prevent double-fire when loadBinary() is called
    // multiple times within the same session.
    disconnect(&analysisWatcher_, &QFutureWatcher<void>::finished,
               this, &MainWindow::onAnalysisFinished);
    connect(&analysisWatcher_, &QFutureWatcher<void>::finished,
            this, &MainWindow::onAnalysisFinished);
    NAVLOG("future set, re-connected onAnalysisFinished (old disconnected)\n");
    GUARD_EXIT("runAnalysisAsync");
}

void MainWindow::onAnalysisFinished() {
    GUARD_ENTER("onAnalysisFinished");
    DBG("program_=%p currentAddr_=0x%llx currentFunction_=%p\n",
        (void*)program_.get(), currentAddr_, (void*)currentFunction_);

    console_->log("+ Analysis completed.");

    // Safety: if currentFunction_ belongs to a previous program, null it out
    if (!isCurrentFunctionValid()) {
        if (currentFunction_) {
            DBG("[onAnalysisFinished] STALE currentFunction_=%p detected (version=%d current=%d), clearing\n",
                (void*)currentFunction_, currentFuncVersion_, programVersion_);
            currentFunction_ = nullptr;
        }
    }

    QApplication::processEvents();

    // VERIFY: program_ and function manager integrity
    if (!program_) {
        DBG("[onAnalysisFinished] program_ null, aborting\n");
        GUARD_EXIT("onAnalysisFinished"); return;
    }
    {
        auto* fm = program_->getFunctionManager();
        auto* sym = program_->getSymbolTable();
        auto* listing = program_->getListing();
        DBG("[DIAG] POST-ANALYSIS: funcCount=%d symCount=%d dataCount=%zu\n",
            fm ? fm->getFunctionCount() : -1,
            sym ? sym->getNumSymbols() : -1,
            listing ? listing->getDataCount() : 0);
        if (fm) {
            ghidra::FunctionIterator fit = fm->getFunctions(true);
            int i = 0;
            while (fit.hasNext() && i < 10) {
                auto* f = fit.next();
                if (f) DBG("[DIAG]   fun[%d]=0x%llx '%s'\n", i,
                    (unsigned long long)f->getEntryPoint().getOffset(), f->getName().c_str());
                i++;
            }
        }
    }

    DBG("[onAnalysisFinished] clearing explorer...\n");
    explorer_->clear();
    DBG("[onAnalysisFinished] re-populating explorer...\n");
    try {
        populateExplorer();
    } catch (const std::exception& e) {
        DBG("[onAnalysisFinished] populateExplorer threw: %s - CAUGHT (no crash)\n", e.what());
        console_->log(QString("Analysis: populateExplorer error: %1").arg(e.what()));
    } catch (...) {
        DBG("[onAnalysisFinished] populateExplorer threw unknown - CAUGHT (no crash)\n");
        console_->log("Analysis: populateExplorer unknown error");
    }

    DBG("[onAnalysisFinished] checking navigation target...\n");
    if (currentAddr_ != 0) {
        DBG("[onAnalysisFinished] navigating to currentAddr_=0x%llx\n", currentAddr_);
        DBG("[onAnalysisFinished] currentFunction_=%p (may be stale!)\n", (void*)currentFunction_);
        navigateTo(currentAddr_, QString());
    } else if (program_) {
        DBG("[onAnalysisFinished] getting functions list...\n");
        auto funcs = decompInterface_->getFunctions();
        if (!funcs.empty()) {
            DBG("[onAnalysisFinished] navigating to first function: 0x%llx '%s'\n",
                funcs[0].entryAddress.getOffset(), funcs[0].name.c_str());
            navigateTo(funcs[0].entryAddress.getOffset(),
                       QString::fromStdString(funcs[0].name));
        } else {
            DBG("[onAnalysisFinished] no functions found, skipping navigation\n");
        }
    }
    GUARD_EXIT("onAnalysisFinished");
}

void MainWindow::onFunctionSelected(uint64_t addr, const QString& name) {
    GUARD_ENTER("onFunctionSelected");
    NAVLOG("addr=0x%llx name='%s' program_=%p\n", addr, name.toStdString().c_str(), (void*)program_.get());
    if (!program_) { NAVLOG("abort: program_ null\n"); GUARD_EXIT("onFunctionSelected"); return; }
    navigateTo(addr, name);
    GUARD_EXIT("onFunctionSelected");
}

void MainWindow::navigateTo(uint64_t addr, const QString& name) {
    // Debounce: restart timer on each call; only execute after 80ms of no calls.
    pendingNavAddr_ = addr;
    pendingNavName_ = name;
    navTimer_->start();
}

void MainWindow::doNavigate(uint64_t addr, const QString& name) {
    std::cerr << "[doNavigate] ENTER addr=0x" << std::hex << addr << std::dec
              << " name='" << name.toStdString() << "' navBusy_=" << navBusy_ << std::endl;
    GUARD_ENTER("navigateTo");
    NAVLOG("addr=0x%llx name='%s' currentAddr_=0x%llx currentFunction_=%p program_=%p navSkipFlags_=%d\n",
        addr, name.toStdString().c_str(), currentAddr_, (void*)currentFunction_, (void*)program_.get(), navSkipFlags_);

    if (!program_) { std::cerr << "[doNavigate] abort: program_ null" << std::endl; NAVLOG("abort: program_ null\n"); GUARD_EXIT("navigateTo"); return; }
    if (addr == 0) { std::cerr << "[doNavigate] abort: addr==0" << std::endl; NAVLOG("abort: addr==0\n"); GUARD_EXIT("navigateTo"); return; }

    // Blocking re-entrancy guard: drop if already navigating.
    if (navBusy_) { std::cerr << "[doNavigate] REENTRANT DROPPED" << std::endl; NAVLOG("WARNING: re-entrant navigateTo - DROPPED\n"); GUARD_EXIT("navigateTo"); return; }
    navBusy_ = true;

    // Read-lock program while navigating (shared with analysis worker).
    programLock_.lockForRead();

    // Read NAV_SKIP from env on first call
    static bool skipInit = false;
    if (!skipInit) {
        const char* envSkip = getenv("NAV_SKIP");
        if (envSkip) {
            navSkipFlags_ = atoi(envSkip);
            NAVLOG("NAV_SKIP from env = %d\n", navSkipFlags_);
        }
        skipInit = true;
    }

    ghidra::Address address;

    // ── STEP 1: Address construction ──────────────────────────────────────
    NAVLOG("STEP1: building Address from addr=0x%llx\n", addr);
    try {
        auto* af = program_->getAddressFactory();
        NAVLOG("  addressFactory=%p\n", (void*)af);
        if (!af) { NAVLOG("ABORT: addressFactory null\n"); programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return; }
        address = af->oldGetAddressFromLong(addr);
        NAVLOG("  address built: space='%s' offset=0x%llx\n",
            address.getAddressSpace() ? address.getAddressSpace()->getName().c_str() : "(null)",
            address.getOffset());
    } catch (const std::exception& e) {
        NAVLOG("STEP1 CRASHED: %s\n", e.what());
        NAVLOG("CRASH at navigateTo step 1 for addr 0x%llx\n", addr);
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    } catch (...) {
        NAVLOG("STEP1 CRASHED: unknown exception\n");
        NAVLOG("CRASH at navigateTo step 1 for addr 0x%llx\n", addr);
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    }

    // ── STEP 2: Navigation stack ──────────────────────────────────────────
    NAVLOG("STEP2: updating nav stack (currAddr=0x%llx)\n", currentAddr_);
    try {
        if (currentAddr_ != 0 && addr != currentAddr_) {
            backStack_.push(currentAddr_);
            forwardStack_.clear();
            NAVLOG("  pushed to backStack (size=%d)\n", backStack_.size());
        }
        currentAddr_ = addr;
    } catch (const std::exception& e) {
        NAVLOG("STEP2 CRASHED: %s\n", e.what());
        NAVLOG("CRASH at navigateTo step 2 for addr 0x%llx\n", addr);
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    } catch (...) {
        NAVLOG("STEP2 CRASHED: unknown exception\n");
        NAVLOG("CRASH at navigateTo step 2 for addr 0x%llx\n", addr);
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    }

    // ── STEP 3: Lookup function ───────────────────────────────────────────
    if (!(navSkipFlags_ & NavSkip_FunctionLookup)) {
        NAVLOG("STEP3: looking up function at addr\n");
        try {
            auto* funcMgr = program_->getFunctionManager();
            NAVLOG("  funcMgr=%p\n", (void*)funcMgr);
            if (funcMgr) {
                ghidra::Function* newFunc = funcMgr->getFunctionAt(address);
                NAVLOG("  getFunctionAt -> %p\n", (void*)newFunc);
                currentFunction_ = newFunc;
                currentFuncVersion_ = programVersion_;
                if (newFunc) {
                    NAVLOG("  function: '%s' entry=0x%llx bodySize=%d\n",
                        newFunc->getName().c_str(),
                        newFunc->getEntryPoint().getOffset(),
                        newFunc->getBody().getNumAddresses());
                }
            } else {
                currentFunction_ = nullptr;
            }
        } catch (const std::exception& e) {
            NAVLOG("STEP3 CRASHED: %s\n", e.what());
            NAVLOG("CRASH at navigateTo step 3 for addr 0x%llx\n", addr);
            currentFunction_ = nullptr;
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        } catch (...) {
            NAVLOG("STEP3 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 3 for addr 0x%llx\n", addr);
            currentFunction_ = nullptr;
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        }
    } else {
        NAVLOG("STEP3: SKIPPED (NavSkip_FunctionLookup)\n");
    }

    // Sync explorer highlight to the navigated address
    try {
        explorer_->highlightAddress(addr);
    } catch (const std::exception& e) {
        NAVLOG("EXPLORER HIGHLIGHT CRASHED: %s\n", e.what());
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    } catch (...) {
        NAVLOG("EXPLORER HIGHLIGHT CRASHED: unknown exception\n");
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    }

    // ── STEP 4: Status bar update ────────────────────────────────────────
    NAVLOG("STEP4: updating status bar\n");
    try {
        statusFunc_->setText(name);
        statusAddr_->setText(QString("0x%1").arg(addr, 0, 16));
    } catch (const std::exception& e) {
        NAVLOG("STEP4 CRASHED: %s\n", e.what());
        NAVLOG("CRASH at navigateTo step 4 for addr 0x%llx\n", addr);
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    } catch (...) {
        NAVLOG("STEP4 CRASHED: unknown exception\n");
        NAVLOG("CRASH at navigateTo step 4 for addr 0x%llx\n", addr);
        programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
    }

    // ── STEP 5: Disassemble ──────────────────────────────────────────────
    if (!(navSkipFlags_ & NavSkip_Disasm)) {
        NAVLOG("STEP5: disassembleAt(0x%llx)...\n", addr);

        // DIRECT: always use disassembleAt (skip buildFullIndex)
        QString asmText;
        try {
            bool disasmOk = decompInterface_ && decompInterface_->isOpen();
            NAVLOG("  decompInterface_->isOpen()=%d\n", disasmOk);
            if (disasmOk) {
                asmText = QString::fromStdString(
                    decompInterface_->disassembleAt(address, 50));
                NAVLOG("  disassembly produced %d chars\n", asmText.size());
            } else {
                NAVLOG("  disassembly SKIPPED (decompInterface not open)\n");
            }
        } catch (const std::exception& e) {
            NAVLOG("STEP5 CRASHED: %s\n", e.what());
            NAVLOG("CRASH at navigateTo step 5 for addr 0x%llx\n", addr);
            std::cerr << "[doNavigate] STEP5 CRASHED: " << e.what() << std::endl;
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        } catch (...) {
            NAVLOG("STEP5 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 5 for addr 0x%llx\n", addr);
            std::cerr << "[doNavigate] STEP5 CRASHED: unknown" << std::endl;
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        }

        try {
            if (!asmText.isEmpty()) {
                NAVLOG("STEP5b: showDisassembly...\n");
                disasmView_->showDisassembly(asmText);
                NAVLOG("  showDisassembly done\n");
            } else {
                NAVLOG("STEP5b: disassembly empty, showing diagnostic\n");
                std::cerr << "[doNavigate] disassembleAt returned empty for 0x" << std::hex << addr << std::dec << std::endl;
                QString diag = QString(
                    "; Disassembly returned no output for 0x%1\n"
                    "; isOpen=%2\n")
                    .arg(addr, 0, 16)
                    .arg(decompInterface_ ? (decompInterface_->isOpen() ? "yes" : "no") : "null");
                std::cerr << "[doNavigate] calling showDisassembly with diagnostic" << std::endl;
                disasmView_->showDisassembly(diag);
                std::cerr << "[doNavigate] after showDisassembly (diagnostic), document="
                          << (void*)disasmView_->document()
                          << " lineCount="
                          << (disasmView_->document() ? disasmView_->document()->lineCount() : 0)
                          << std::endl;
            }
        } catch (const std::exception& e) {
            NAVLOG("STEP5b CRASHED: %s\n", e.what());
            NAVLOG("CRASH at navigateTo step 5b for addr 0x%llx\n", addr);
            std::cerr << "[doNavigate] STEP5b CRASHED: " << e.what() << std::endl;
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        } catch (...) {
            NAVLOG("STEP5b CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 5b for addr 0x%llx\n", addr);
            std::cerr << "[doNavigate] STEP5b CRASHED: unknown" << std::endl;
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        }
    } else {
        NAVLOG("STEP5: SKIPPED (NavSkip_Disasm)\n");
    }

    // GUARANTEE: ensure the disassembly view has a document, even if everything above failed
    std::cerr << "[doNavigate] PRE-GUARANTEE: document="
              << (void*)disasmView_->document()
              << " lineCount="
              << (disasmView_->document() ? disasmView_->document()->lineCount() : 0)
              << std::endl;
    if (!disasmView_->document() || disasmView_->document()->lineCount() == 0) {
        std::cerr << "[doNavigate] WARNING: disassembly view has no document after STEP5!" << std::endl;
        disasmView_->showDisassembly(QString(
            "; NO DISASSEMBLY\n"
            "; doNavigate reached addr=0x%1\n"
            "; Check stderr\n")
            .arg(addr, 0, 16));
    }
    std::cerr << "[doNavigate] POST-GUARANTEE: document="
              << (void*)disasmView_->document()
              << " lineCount="
              << (disasmView_->document() ? disasmView_->document()->lineCount() : 0)
              << std::endl;

    // ── STEP 6: Decompile ─────────────────────────────────────────────────
    if (!(navSkipFlags_ & NavSkip_Decompile)) {
        NAVLOG("STEP6: decompile or cache lookup\n");
        try {
            auto it = decompCache_.find(addr);
            if (it != decompCache_.end()) {
                NAVLOG("  cache HIT (size=%d)\n", it->second.cCode.size());
                decompView_->showDecompiled(it->second.cCode, addr,
                    it->second.markupXml, it->second.opAddresses);
            } else {
                NAVLOG("  cache MISS, calling decompileFunction...\n");
                auto results = decompInterface_->decompileFunction(address, nullptr);
                NAVLOG("  decompileFunction returned: decompiled=%d cCodeSize=%d funcName='%s'\n",
                    results.decompiled, (int)results.cCode.size(), results.functionName.c_str());
                if (results.decompiled) {
                    QString cCode = QString::fromStdString(results.cCode);
                    DecompCacheEntry entry;
                    entry.cCode = cCode;
                    entry.markupXml = QString::fromStdString(results.markupXml);
                    entry.opAddresses = results.opAddresses;
                    decompCache_[addr] = entry;
                    evictDecompCache();
                    NAVLOG("  calling showDecompiled cCode.size()=%d markup.size()=%d opAddrs.size()=%zu\n",
                        cCode.size(), entry.markupXml.size(), entry.opAddresses.size());
                    decompView_->showDecompiled(cCode, addr,
                        entry.markupXml, entry.opAddresses);
                    NAVLOG("  showDecompiled done, decompView visible=%d size=(%dx%d)\n",
                        decompView_->isVisible(), decompView_->width(), decompView_->height());
                } else {
                    NAVLOG("  decompile FAILED, clearing decompiler\n");
                    decompView_->clear();
                }
            }
        } catch (const std::exception& e) {
            NAVLOG("STEP6 CRASHED: %s\n", e.what());
            NAVLOG("CRASH at navigateTo step 6 for addr 0x%llx\n", addr);
            decompView_->clear();
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        } catch (...) {
            NAVLOG("STEP6 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 6 for addr 0x%llx\n", addr);
            decompView_->clear();
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        }
    } else {
        NAVLOG("STEP6: SKIPPED (NavSkip_Decompile)\n");
    }

    // ── STEP 7: Hex view (full-program hex dump, sync navigation) ───────
    if (!(navSkipFlags_ & NavSkip_Hex)) {
        NAVLOG("STEP7: building full hex / seeking\n");
        try {
            if (!hexView_->document() || hexView_->document()->lineCount() == 0) {
                NAVLOG("  building full hex listing\n");
                hexView_->buildFullHex(program_.get(), currentBinaryPath_);
            }
            if (hexView_->document() && hexView_->document()->lineCount() > 0) {
                NAVLOG("  seeking hex to 0x%llx\n", addr);
                hexView_->seek(addr);
            }
        } catch (const std::exception& e) {
            NAVLOG("STEP7 CRASHED: %s\n", e.what());
            NAVLOG("CRASH at navigateTo step 7 for addr 0x%llx\n", addr);
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        } catch (...) {
            NAVLOG("STEP7 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 7 for addr 0x%llx\n", addr);
            programLock_.unlock(); navBusy_ = false; GUARD_EXIT("navigateTo"); return;
        }
    } else {
        NAVLOG("STEP7: SKIPPED (NavSkip_Hex)\n");
    }

    try {
        logOnce(QString("Navigated to: %1 @ 0x%2").arg(name).arg(addr, 0, 16));
    } catch (const std::exception& e) {
        NAVLOG("logOnce CRASHED: %s\n", e.what());
    } catch (...) {
        NAVLOG("logOnce CRASHED: unknown exception\n");
    }
    programLock_.unlock();
    navBusy_ = false;
    NAVLOG("END\n");
    GUARD_EXIT("navigateTo");
}
void MainWindow::onNavigateBack() {
    GUARD_ENTER("onNavigateBack");
    NAVLOG("backStack.size=%d program_=%p currentAddr_=0x%llx\n",
        backStack_.size(), (void*)program_.get(), currentAddr_);
    if (backStack_.isEmpty()) { NAVLOG("abort: backStack empty\n"); GUARD_EXIT("onNavigateBack"); return; }
    if (!program_) { NAVLOG("abort: program_ null\n"); GUARD_EXIT("onNavigateBack"); return; }

    uint64_t addr = backStack_.pop();
    NAVLOG("popped addr=0x%llx\n", addr);
    forwardStack_.push(currentAddr_);
    navigateTo(addr, QString());
    GUARD_EXIT("onNavigateBack");
}

void MainWindow::onNavigateForward() {
    GUARD_ENTER("onNavigateForward");
    NAVLOG("forwardStack.size=%d program_=%p currentAddr_=0x%llx\n",
        forwardStack_.size(), (void*)program_.get(), currentAddr_);
    if (forwardStack_.isEmpty()) { NAVLOG("abort: forwardStack empty\n"); GUARD_EXIT("onNavigateForward"); return; }
    if (!program_) { NAVLOG("abort: program_ null\n"); GUARD_EXIT("onNavigateForward"); return; }
    uint64_t addr = forwardStack_.pop();
    backStack_.push(currentAddr_);
    navigateTo(addr, QString());
    GUARD_EXIT("onNavigateForward");
}

void MainWindow::onDisasmAddressDoubleClicked(uint64_t addr) {
    GUARD_ENTER("onDisasmAddressDoubleClicked");
    NAVLOG("addr=0x%llx program_=%p\n", addr, (void*)program_.get());
    if (!program_) { NAVLOG("abort: program_ null\n"); GUARD_EXIT("onDisasmAddressDoubleClicked"); return; }

    QString name;
    auto* funcMgr = program_->getFunctionManager();
    NAVLOG("  funcMgr=%p\n", (void*)funcMgr);
    ghidra::Address address = program_->getAddressFactory()->oldGetAddressFromLong(addr);
    auto* func = funcMgr ? funcMgr->getFunctionContaining(address) : nullptr;
    NAVLOG("  getFunctionContaining -> %p\n", (void*)func);
    if (func) {
        name = QString::fromStdString(func->getName());
        NAVLOG("  found function '%s' entry=0x%llx\n", name.toStdString().c_str(),
            func->getEntryPoint().getOffset());
        navigateTo(func->getEntryPoint().getOffset(), name);
    } else {
        NAVLOG("  no function at addr, trying symbol table\n");
        auto syms = program_->getSymbolTable()->getSymbols(address);
        if (!syms.empty() && syms[0]) name = QString::fromStdString(syms[0]->getName());
        if (name.isEmpty()) name = QString("0x%1").arg(addr, 0, 16);
        NAVLOG("  navigating to raw addr with name='%s'\n", name.toStdString().c_str());
        navigateTo(addr, name);
    }
    GUARD_EXIT("onDisasmAddressDoubleClicked");
}

void MainWindow::onDecompAddressDoubleClicked(uint64_t addr) {
    GUARD_ENTER("onDecompAddressDoubleClicked");
    NAVLOG("addr=0x%llx\n", addr);
    onDisasmAddressDoubleClicked(addr);
    GUARD_EXIT("onDecompAddressDoubleClicked");
}

void MainWindow::onToggleShowBytes(bool show) {
    if (disasmView_)
        disasmView_->setShowBytes(show);
}

void MainWindow::logOnce(const QString& msg) {
    if (msg != lastConsoleMsg_) {
        console_->log(msg);
        lastConsoleMsg_ = msg;
    }
}

void MainWindow::onAddressCursorSync(uint64_t addr) {
    if (addr == 0 || !program_) return;

    // Update status bar
    statusAddr_->setText(QString("0x%1").arg(addr, 0, 16));

    QObject* s = sender();

    // Scroll disasm to the same address
    if (s != disasmView_)
        disasmView_->seek(addr);

    // Scroll decompiler to the same address
    if (s != decompView_)
        decompView_->seek(addr);

    if (s != hexView_) {
        if (!hexView_->document() || hexView_->document()->lineCount() == 0) {
            hexView_->buildFullHex(program_.get(), currentBinaryPath_);
        }
        if (hexView_->containsAddress(addr)) {
            hexView_->seek(addr);
        }
    }
}

void MainWindow::onCommit() {
    if (!program_) {
        console_->log("No program loaded.");
        return;
    }
    if (repoPath_.empty()) {
        console_->log("Save the project first (Ctrl+S).");
        return;
    }
    std::string currentBranch = ghidra::storage::BranchManager::getCurrentBranch(repoPath_);
    std::string parentCommitId = ghidra::storage::BranchManager::getBranchCommit(repoPath_, currentBranch);
    bool ok = false;
    QString msg = QInputDialog::getMultiLineText(this, tr("Commit"),
        tr("Commit message:"), "", &ok);
    if (!ok) return;
    std::string commitId = ghidra::storage::CommitManager::createCommit(
        repoPath_, parentCommitId, msg.toStdString(), "user", currentBranch,
        *program_, eventLog_);
    if (!commitId.empty()) {
        eventLog_.clear();
        updateUndoRedoActions();
        console_->log("Commit created: " + QString::fromStdString(commitId).left(12));
    } else {
        console_->log("Failed to create commit.");
    }
}

void MainWindow::onCommitHistory() {
    if (repoPath_.empty()) {
        console_->log("No project open.");
        return;
    }
    auto commitIds = ghidra::storage::CommitManager::listCommits(repoPath_);
    if (commitIds.empty()) {
        QMessageBox::information(this, tr("Commit History"), tr("No commits yet."));
        return;
    }

    struct DisplayEntry {
        std::string id;
        std::string branchName;
        std::string message;
        uint64_t timestamp;
        DisplayEntry(std::string i, std::string b, std::string m, uint64_t t)
            : id(std::move(i)), branchName(std::move(b)), message(std::move(m)), timestamp(t) {}
    };
    std::vector<DisplayEntry> entries;
    for (const auto& cid : commitIds) {
        ghidra::storage::CommitInfo info;
        if (ghidra::storage::CommitManager::loadCommitMeta(repoPath_, cid, info)) {
            entries.push_back(DisplayEntry(info.commitId, info.branchName, info.message, info.timestamp));
        }
    }
    if (entries.empty()) {
        QMessageBox::information(this, tr("Commit History"), tr("No commit metadata found."));
        return;
    }

    QStringList items;
    for (const auto& e : entries) {
        QString label = QString("%1 | %2 | %3")
            .arg(QString::fromStdString(e.id).left(12), -12)
            .arg(QString::fromStdString(e.branchName), -10)
            .arg(QString::fromStdString(e.message));
        items << label;
    }

    bool ok = false;
    QString chosen = QInputDialog::getItem(this, tr("Commit History"),
        tr("Select commit to check out:"), items, 0, false, &ok);
    if (!ok) return;
    int idx = items.indexOf(chosen);
    if (idx < 0 || idx >= static_cast<int>(entries.size())) return;

    auto ret = QMessageBox::question(this, tr("Checkout Commit"),
        tr("Checkout commit %1?\nThis will replace the current working state.")
            .arg(QString::fromStdString(entries[idx].id).left(12)));
    if (ret != QMessageBox::Yes) return;

    try {
        if (!program_ || !decompInterface_ || !disasmView_ || !explorer_) {
            QMessageBox::warning(this, tr("Error"), tr("UI not initialized."));
            return;
        }

        std::string snapPath = ghidra::storage::Repository::getWorkingSnapshotPath(repoPath_);
        ghidra::storage::WorkingSnapshot::save(*program_, snapPath);

        std::string commitSnapPath = ghidra::storage::Repository::getCommitSnapshotPath(repoPath_, entries[idx].id);
        auto prog = ghidra::storage::WorkingSnapshot::load(commitSnapPath);
        if (!prog) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to load commit snapshot."));
            return;
        }

        if (analysisWatcher_.isRunning()) analysisWatcher_.waitForFinished();
        analysisMgr_.reset();
        decompCache_.clear();
        backStack_.clear();
        forwardStack_.clear();
        currentFunction_ = nullptr;
        currentAddr_ = 0;
        eventLog_.clear();

        decompInterface_->closeProgram();
        program_.reset(prog.release());
        if (!program_) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to load program from snapshot."));
            return;
        }
        if (!decompInterface_->openProgram(program_.get())) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to open program in decompiler."));
            return;
        }

        disasmView_->setProgram(program_.get());
        disasmView_->setDecompInterface(decompInterface_.get());
        ghidra::storage::WorkingSnapshot::save(*program_, snapPath);
        populateExplorer();
        ghidra::storage::IndexManager::rebuildFromProgramDB(repoPath_, *program_);
        runAnalysisAsync();

        setWindowTitle(tr("Enigma Engine \u2014 %1 [commit %2]")
            .arg(QString::fromStdString(program_->getName()))
            .arg(QString::fromStdString(entries[idx].id).left(12)));
        console_->log("Checked out commit: " + QString::fromStdString(entries[idx].id).left(12));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"),
            tr("Checkout failed: %1").arg(e.what()));
    } catch (...) {
        QMessageBox::warning(this, tr("Error"),
            tr("Checkout failed with unknown error."));
    }
}

void MainWindow::onCreateBranch() {
    if (repoPath_.empty()) {
        console_->log("No project open.");
        return;
    }
    bool ok = false;
    QString name = QInputDialog::getText(this, tr("Create Branch"),
        tr("Branch name:"), QLineEdit::Normal, "", &ok);
    if (!ok || name.isEmpty()) return;
    std::string currentBranch = ghidra::storage::BranchManager::getCurrentBranch(repoPath_);
    std::string headCommit = ghidra::storage::BranchManager::getBranchCommit(repoPath_, currentBranch);
    if (headCommit.empty()) {
        console_->log("Current branch has no commits yet. Make a commit first (Ctrl+K).");
        return;
    }
    if (!ghidra::storage::BranchManager::createBranch(repoPath_, name.toStdString(), headCommit)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to create branch (may already exist)."));
        return;
    }
    console_->log("Created branch: " + name);
}

void MainWindow::onSwitchBranch() {
    if (repoPath_.empty()) {
        console_->log("No project open.");
        return;
    }
    auto branches = ghidra::storage::BranchManager::listBranches(repoPath_);
    if (branches.empty()) {
        console_->log("No branches available.");
        return;
    }
    QStringList names;
    for (const auto& b : branches) names << QString::fromStdString(b.name);

    std::string currentBranch = ghidra::storage::BranchManager::getCurrentBranch(repoPath_);
    int currentIdx = names.indexOf(QString::fromStdString(currentBranch));
    if (currentIdx < 0) currentIdx = 0;

    bool ok = false;
    QString chosen = QInputDialog::getItem(this, tr("Switch Branch"),
        tr("Select branch:"), names, currentIdx, false, &ok);
    if (!ok || chosen.isEmpty()) return;
    std::string branchName = chosen.toStdString();
    std::string headCommit = ghidra::storage::BranchManager::getBranchCommit(repoPath_, branchName);
    if (headCommit.empty()) {
        console_->log("Branch '" + chosen + "' has no commits.");
        return;
    }

    try {
        if (!program_ || !decompInterface_ || !disasmView_ || !explorer_) {
            QMessageBox::warning(this, tr("Error"), tr("UI not initialized."));
            return;
        }

        std::string snapPath = ghidra::storage::Repository::getWorkingSnapshotPath(repoPath_);
        ghidra::storage::WorkingSnapshot::save(*program_, snapPath);

        if (!ghidra::storage::BranchManager::switchBranch(repoPath_, branchName)) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to switch branch."));
            return;
        }

        std::string commitSnapPath = ghidra::storage::Repository::getCommitSnapshotPath(repoPath_, headCommit);
        auto prog = ghidra::storage::WorkingSnapshot::load(commitSnapPath);
        if (!prog) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to load branch snapshot."));
            return;
        }

        if (analysisWatcher_.isRunning()) analysisWatcher_.waitForFinished();
        analysisMgr_.reset();
        decompCache_.clear();
        backStack_.clear();
        forwardStack_.clear();
        currentFunction_ = nullptr;
        currentAddr_ = 0;
        eventLog_.clear();

        decompInterface_->closeProgram();
        program_.reset(prog.release());
        if (!program_) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to load program from snapshot."));
            return;
        }
        if (!decompInterface_->openProgram(program_.get())) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to open program in decompiler."));
            return;
        }

        disasmView_->setProgram(program_.get());
        disasmView_->setDecompInterface(decompInterface_.get());
        ghidra::storage::WorkingSnapshot::save(*program_, snapPath);
        populateExplorer();
        ghidra::storage::IndexManager::rebuildFromProgramDB(repoPath_, *program_);
        runAnalysisAsync();

        setWindowTitle(tr("Enigma Engine \u2014 %1 [%2]")
            .arg(QString::fromStdString(program_->getName()))
            .arg(chosen));
        console_->log("Switched to branch: " + chosen);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"),
            tr("Branch switch failed: %1").arg(e.what()));
    } catch (...) {
        QMessageBox::warning(this, tr("Error"),
            tr("Branch switch failed with unknown error."));
    }
}

void MainWindow::onClearIndex() {
    autoClearIndex_ = false;
    explorer_->autoClearCheckbox()->setChecked(false);
    console_->log("> Clearing FKS index...");
    QApplication::processEvents();
    std::string fksDir = resolveFksDir();
    if (!fksDir.empty()) {
        console_->log(QString("  FKS dir: %1").arg(QString::fromStdString(fksDir)));
        std::string error;
        if (ghidra::storage::FksIndexManager::clear(fksDir, &error)) {
            console_->log("  FKS index cleared (data.mdb emptied).");
        } else {
            console_->log("  Failed to clear FKS index.");
            if (!error.empty())
                console_->log(QString("  Error: %1").arg(QString::fromStdString(error)));
        }
    } else {
        console_->log("  No writable FKS index found; nothing to clear.");
    }
}

void MainWindow::onAutoClearToggled(bool checked) {
    autoClearIndex_ = checked;
    explorer_->autoClearCheckbox()->setChecked(checked);
    console_->log(QString("Auto clear index: %1").arg(checked ? "ON" : "OFF"));
}

void MainWindow::onUndo() {
    console_->log("Undo not yet implemented.");
}
void MainWindow::onRedo() {
    console_->log("Redo not yet implemented.");
}

void MainWindow::onRenameFunction() {
    if (!program_ || !isCurrentFunctionValid() || !patchManager_) {
        console_->log("No function selected.");
        return;
    }
    bool ok = false;
    QString newName = QInputDialog::getText(this, tr("Rename Function"),
        tr("New name for '%1':")
            .arg(QString::fromStdString(currentFunction_->getName())),
        QLineEdit::Normal,
        QString::fromStdString(currentFunction_->getName()), &ok);
    if (!ok || newName.isEmpty()) return;

    std::string oldName = currentFunction_->getName();
    uint64_t entryAddr = currentFunction_->getEntryPoint().getOffset();
    if (newName.toStdString() == oldName) {
        console_->log("Name unchanged.");
        return;
    }

    auto patch = std::make_unique<ghidra::patch::FunctionRenamePatch>(
        entryAddr, oldName, newName.toStdString());
    ghidra::patch::Patch* rawPatch = patch.get();
    patchManager_->addPatch(std::move(patch));

    // Actually apply the rename to the program so it's immediately visible
    ghidra::ProgramDB* prog = patchManager_->program();
    ghidra::Memory* mem = prog ? prog->getMemory() : nullptr;
    if (mem && prog && rawPatch->apply(*mem, *prog)) {
        rawPatch->setApplied(true);
        console_->log(QString("Function renamed: \"%1\" -> \"%2\"")
            .arg(QString::fromStdString(oldName)).arg(newName));
        // Refresh the explorer to show the new name
        populateExplorer();
    } else {
        console_->log(QString("Function rename failed: \"%1\" -> \"%2\"")
            .arg(QString::fromStdString(oldName)).arg(newName));
    }
}

void MainWindow::onDeleteFunction() {
    if (!program_ || !isCurrentFunctionValid() || !patchManager_) {
        console_->log("No function selected.");
        return;
    }
    QString name = QString::fromStdString(currentFunction_->getName());
    uint64_t addr = currentFunction_->getEntryPoint().getOffset();
    auto ret = QMessageBox::question(this, tr("Delete Function"),
        tr("Delete function '%1' @ 0x%2?")
            .arg(name).arg(addr, 0, 16));
    if (ret != QMessageBox::Yes) return;

    auto patch = std::make_unique<ghidra::patch::FunctionDeletePatch>(
        addr, name.toStdString());
    patchManager_->addPatch(std::move(patch));
    console_->log(QString("Function deleted: %1").arg(name));
}

void MainWindow::onAddLabel() {
    if (!program_ || !patchManager_ || currentAddr_ == 0) {
        console_->log("No address selected.");
        return;
    }
    bool ok = false;
    QString name = QInputDialog::getText(this, tr("Add Label"),
        tr("Label name at 0x%1:").arg(currentAddr_, 0, 16),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || name.isEmpty()) return;

    auto patch = std::make_unique<ghidra::patch::SymbolCreatePatch>(
        currentAddr_, name.toStdString());
    patchManager_->addPatch(std::move(patch));
    console_->log(QString("Label added: %1 @ 0x%2")
        .arg(name).arg(currentAddr_, 0, 16));
}

void MainWindow::onRemoveLabel() {
    if (!program_ || !patchManager_ || currentAddr_ == 0) {
        console_->log("No address selected.");
        return;
    }
    auto* symTable = program_->getSymbolTable();
    if (!symTable) return;
    auto af = program_->getAddressFactory();
    ghidra::Address addr = af->oldGetAddressFromLong(currentAddr_);
    auto symbols = symTable->getSymbols(addr);
    if (symbols.empty()) {
        console_->log("No labels at this address.");
        return;
    }
    QStringList items;
    for (auto* s : symbols) {
        if (s) items << QString::fromStdString(s->getName());
    }
    bool ok = false;
    QString chosen = QInputDialog::getItem(this, tr("Remove Label"),
        tr("Select label to remove at 0x%1:").arg(currentAddr_, 0, 16),
        items, 0, false, &ok);
    if (!ok || chosen.isEmpty()) return;

    auto patch = std::make_unique<ghidra::patch::SymbolDeletePatch>(
        currentAddr_, chosen.toStdString());
    patchManager_->addPatch(std::move(patch));
    console_->log(QString("Label removed: %1 @ 0x%2")
        .arg(chosen).arg(currentAddr_, 0, 16));
}

void MainWindow::onSetComment() {
    if (!program_ || !patchManager_ || currentAddr_ == 0) {
        console_->log("No address selected.");
        return;
    }
    bool ok = false;
    QString text = QInputDialog::getMultiLineText(this, tr("Set Comment"),
        tr("Comment at 0x%1:").arg(currentAddr_, 0, 16),
        QString(), &ok);
    if (!ok) return;

    // Read existing comment text for revert
    std::string oldText;
    auto* listing = program_->getListing();
    if (listing) {
        auto af = program_->getAddressFactory();
        ghidra::Address addr = af->oldGetAddressFromLong(currentAddr_);
        auto* cu = listing->getCodeUnitAt(addr);
        if (cu) oldText = cu->getComment();
    }

    auto patch = std::make_unique<ghidra::patch::CommentPatch>(
        currentAddr_,
        ghidra::patch::CommentPatch::CommentType::EOL,
        oldText, text.toStdString());
    patchManager_->addPatch(std::move(patch));
    console_->log(QString("Comment set @ 0x%1").arg(currentAddr_, 0, 16));
}

void MainWindow::onRemoveComment() {
    if (!program_ || !patchManager_ || currentAddr_ == 0) {
        console_->log("No address selected.");
        return;
    }
    auto* listing = program_->getListing();
    if (!listing) return;
    auto af = program_->getAddressFactory();
    ghidra::Address addr = af->oldGetAddressFromLong(currentAddr_);
    auto* cu = listing->getCodeUnitAt(addr);
    if (!cu || cu->getComment().empty()) {
        console_->log("No comment at this address.");
        return;
    }
    std::string oldText = cu->getComment();

    auto patch = std::make_unique<ghidra::patch::CommentPatch>(
        currentAddr_,
        ghidra::patch::CommentPatch::CommentType::EOL,
        oldText, "");
    patchManager_->addPatch(std::move(patch));
    console_->log(QString("Comment removed @ 0x%1").arg(currentAddr_, 0, 16));
}

void MainWindow::onAddBookmark() {
    if (!program_ || !patchManager_ || currentAddr_ == 0) {
        console_->log("No address selected.");
        return;
    }
    bool ok = false;
    QString text = QInputDialog::getText(this, tr("Add Bookmark"),
        tr("Bookmark note at 0x%1:").arg(currentAddr_, 0, 16),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || text.isEmpty()) return;

    auto patch = std::make_unique<ghidra::patch::BookmarkPatch>(
        currentAddr_, text.toStdString(), true);
    patchManager_->addPatch(std::move(patch));
    console_->log(QString("Bookmark added @ 0x%1").arg(currentAddr_, 0, 16));
}

void MainWindow::onDeleteBookmark() {
    if (!program_ || !patchManager_ || currentAddr_ == 0) {
        console_->log("No address selected.");
        return;
    }
    auto af = program_->getAddressFactory();
    ghidra::Address addr = af->oldGetAddressFromLong(currentAddr_);
    auto* bmMgr = program_->getBookmarkManager();
    if (!bmMgr) return;
    if (!bmMgr->getBookmark(addr, "Note")) {
        console_->log("No bookmark at this address.");
        return;
    }

    auto patch = std::make_unique<ghidra::patch::BookmarkPatch>(
        currentAddr_, "", false);
    patchManager_->addPatch(std::move(patch));
    console_->log(QString("Bookmark deleted @ 0x%1").arg(currentAddr_, 0, 16));
}

void MainWindow::onExportPatchedBinary() {
    if (!patchManager_ || patchManager_->patchCount() == 0) {
        console_->log("No patches to export.");
        return;
    }
    QString path = QFileDialog::getSaveFileName(this, tr("Export Patched Binary"),
        QString(), tr("Executable (*.exe *.dll *.elf *.so *.bin);;All Files (*)"));
    if (path.isEmpty()) return;
    if (patchManager_->exportPatchedBinary(path.toStdString())) {
        console_->log("Patched binary exported to: " + path);
    } else {
        console_->log("Failed to export patched binary.");
    }
}

void MainWindow::onShowPatchList() {
    if (!patchManager_) return;
    auto patches = patchManager_->getAllPatches();
    if (patches.empty()) {
        console_->log("No patches applied.");
        return;
    }
    console_->log(QString("--- Patch List (%1 patches) ---").arg(patches.size()));
    for (const auto* p : patches) {
        QString status = (p->enabled() && p->applied()) ? "ACTIVE" : "DISABLED";
        console_->log(QString("  [%1] %2").arg(status).arg(QString::fromStdString(p->previewText())));
    }
}

void MainWindow::onRevertAllPatches() {
    if (!patchManager_ || patchManager_->patchCount() == 0) {
        console_->log("No patches to revert.");
        return;
    }
    auto ret = QMessageBox::question(this, tr("Revert All"),
        tr("Revert all %1 patches?\nThis will undo all pending changes.")
            .arg(patchManager_->patchCount()));
    if (ret != QMessageBox::Yes) return;
    patchManager_->revertAll();
    console_->log("All patches reverted.");
    if (hexView_) hexView_->viewport()->update();
}

void MainWindow::executeWithEvent(std::unique_ptr<ghidra::storage::Event> event) {}
void MainWindow::updateUndoRedoActions() {}
