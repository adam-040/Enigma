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
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/WorkingSnapshot.h>
#include <ghidra/storage/BranchManager.h>
#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/IndexManager.h>


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
    edit->addAction(tr("&Undo"));
    edit->addAction(tr("&Redo"));

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

    menuBar()->addMenu(tr("&Tools"));
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
    QApplication::processEvents();

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

    analysisMgr_.reset();
    decompCache_.clear();
    backStack_.clear();
    forwardStack_.clear();
    currentFunction_ = nullptr;
    currentAddr_ = 0;

    program_.reset(prog);
    DBG("[loadBinary] calling decompInterface_->closeProgram...\n");
    decompInterface_->closeProgram();
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
    try {
        if (!decompInterface_->openProgram(prog)) {
            DBG("[loadBinary] openProgram returned false\n");
            QMessageBox::warning(this, tr("Error"), tr("Failed to open program in decompiler."));
            return;
        }
    } catch (const std::exception& e) {
        DBG("[loadBinary] openProgram threw: %s\n", e.what());
        QMessageBox::warning(this, tr("Error"), tr("openProgram threw: %1").arg(e.what()));
        return;
    } catch (...) {
        DBG("[loadBinary] openProgram threw unknown\n");
        QMessageBox::warning(this, tr("Error"), tr("openProgram threw unknown exception"));
        return;
    }
    DBG("[loadBinary] openProgram succeeded\n");
    disasmView_->setProgram(program_.get());
    disasmView_->setDecompInterface(decompInterface_.get());

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
        NAVLOG("populateExplorer THREW: %s\n", e.what());
        NAVLOG("RETHROWING - will crash via terminate\n");
        throw;
    }
    NAVLOG("populateExplorer done\n");

    console_->log(QString("Binary loaded: %1").arg(binaryName));
    console_->log(QString("Architecture: %1-bit %2%3")
        .arg(loader->getBitness())
        .arg(loader->getArchitecture().c_str())
        .arg(loader->isBigEndian() ? " BE" : " LE"));

    NAVLOG("calling runAnalysisAsync...\n");
    runAnalysisAsync();
    GUARD_EXIT("loadBinary");
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
    for (auto& f : funcs) {
        uint64_t addr = f.entryAddress.getOffset();
        explorer_->addEntry(root, addr, QString::fromStdString(f.name));
    }

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
    if (currentFunction_ && program_) {
        auto* fm = program_->getFunctionManager();
        if (fm) {
            ghidra::Function* check = fm->getFunctionAt(currentFunction_->getEntryPoint());
            if (check != currentFunction_) {
                DBG("[onAnalysisFinished] STALE currentFunction_=%p detected, clearing\n",
                    (void*)currentFunction_);
                currentFunction_ = nullptr;
            }
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
        DBG("[onAnalysisFinished] populateExplorer threw: %s\n", e.what());
        DBG("[onAnalysisFinished] RETHROWING: this will probably crash\n");
        throw;
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
    GUARD_ENTER("navigateTo");
    NAVLOG("addr=0x%llx name='%s' currentAddr_=0x%llx currentFunction_=%p program_=%p navSkipFlags_=%d\n",
        addr, name.toStdString().c_str(), currentAddr_, (void*)currentFunction_, (void*)program_.get(), navSkipFlags_);

    if (!program_) { NAVLOG("abort: program_ null\n"); GUARD_EXIT("navigateTo"); return; }
    if (addr == 0) { NAVLOG("abort: addr==0\n"); GUARD_EXIT("navigateTo"); return; }

    // Track re-entrant calls
    static thread_local int navDepth = 0;
    NAVLOG("navDepth=%d\n", navDepth);
    if (navDepth > 0) { NAVLOG("WARNING: re-entrant navigateTo!\n"); }
    ++navDepth;

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
        if (!af) { NAVLOG("ABORT: addressFactory null\n"); --navDepth; GUARD_EXIT("navigateTo"); return; }
        address = af->oldGetAddressFromLong(addr);
        NAVLOG("  address built: space='%s' offset=0x%llx\n",
            address.getAddressSpace() ? address.getAddressSpace()->getName().c_str() : "(null)",
            address.getOffset());
    } catch (const std::exception& e) {
        NAVLOG("STEP1 CRASHED: %s\n", e.what());
        NAVLOG("CRASH at navigateTo step 1 for addr 0x%llx\n", addr);
        --navDepth; GUARD_EXIT("navigateTo"); return;
    } catch (...) {
        NAVLOG("STEP1 CRASHED: unknown exception\n");
        NAVLOG("CRASH at navigateTo step 1 for addr 0x%llx\n", addr);
        --navDepth; GUARD_EXIT("navigateTo"); return;
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
        --navDepth; GUARD_EXIT("navigateTo"); return;
    } catch (...) {
        NAVLOG("STEP2 CRASHED: unknown exception\n");
        NAVLOG("CRASH at navigateTo step 2 for addr 0x%llx\n", addr);
        --navDepth; GUARD_EXIT("navigateTo"); return;
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
        } catch (...) {
            NAVLOG("STEP3 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 3 for addr 0x%llx\n", addr);
            currentFunction_ = nullptr;
        }
    } else {
        NAVLOG("STEP3: SKIPPED (NavSkip_FunctionLookup)\n");
    }

    // Sync explorer highlight to the navigated address
    explorer_->highlightAddress(addr);

    // ── STEP 4: Status bar update ────────────────────────────────────────
    NAVLOG("STEP4: updating status bar\n");
    try {
        statusFunc_->setText(name);
        statusAddr_->setText(QString("0x%1").arg(addr, 0, 16));
    } catch (const std::exception& e) {
        NAVLOG("STEP4 CRASHED: %s\n", e.what());
        NAVLOG("CRASH at navigateTo step 4 for addr 0x%llx\n", addr);
        --navDepth; GUARD_EXIT("navigateTo"); return;
    } catch (...) {
        NAVLOG("STEP4 CRASHED: unknown exception\n");
        NAVLOG("CRASH at navigateTo step 4 for addr 0x%llx\n", addr);
        --navDepth; GUARD_EXIT("navigateTo"); return;
    }

    // ── STEP 5: Disassemble ──────────────────────────────────────────────
    QString asmText;
    if (!(navSkipFlags_ & NavSkip_Disasm)) {
        NAVLOG("STEP5: disassembleAt(0x%llx)...\n", addr);
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
            asmText = QString();
        } catch (...) {
            NAVLOG("STEP5 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 5 for addr 0x%llx\n", addr);
            asmText = QString();
        }

        try {
            if (!asmText.isEmpty()) {
                NAVLOG("STEP5b: showDisassembly...\n");
                disasmView_->showDisassembly(asmText);
                NAVLOG("  showDisassembly done\n");
            } else {
                NAVLOG("STEP5b: clearing disassembly (empty text)\n");
                disasmView_->clearDocument();
            }
        } catch (const std::exception& e) {
            NAVLOG("STEP5b CRASHED: %s\n", e.what());
            NAVLOG("CRASH at navigateTo step 5b for addr 0x%llx\n", addr);
        } catch (...) {
            NAVLOG("STEP5b CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 5b for addr 0x%llx\n", addr);
        }
    } else {
        NAVLOG("STEP5: SKIPPED (NavSkip_Disasm)\n");
    }

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
        } catch (...) {
            NAVLOG("STEP6 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 6 for addr 0x%llx\n", addr);
        }
    } else {
        NAVLOG("STEP6: SKIPPED (NavSkip_Decompile)\n");
    }

    // ── STEP 7: Hex view ─────────────────────────────────────────────────
    if (!(navSkipFlags_ & NavSkip_Hex)) {
        NAVLOG("STEP7: reading memory bytes for hex view\n");
        try {
            auto* mem = program_->getMemory();
            NAVLOG("  memory=%p\n", (void*)mem);
            if (mem) {
                std::vector<uint8_t> bytes(256);
                int got = mem->getBytes(address, bytes.data(), 256);
                NAVLOG("  getBytes returned %d\n", got);
                if (got > 0) {
                    bytes.resize(got);
                    hexView_->setData(addr, bytes);
                } else {
                    NAVLOG("  clearing hex view\n");
                    hexView_->clear();
                }
            } else {
                NAVLOG("  memory null, clearing hex view\n");
                hexView_->clear();
            }
        } catch (const std::exception& e) {
            NAVLOG("STEP7 CRASHED: %s\n", e.what());
            NAVLOG("CRASH at navigateTo step 7 for addr 0x%llx\n", addr);
        } catch (...) {
            NAVLOG("STEP7 CRASHED: unknown exception\n");
            NAVLOG("CRASH at navigateTo step 7 for addr 0x%llx\n", addr);
        }
    } else {
        NAVLOG("STEP7: SKIPPED (NavSkip_Hex)\n");
    }

    logOnce(QString("Navigated to: %1 @ 0x%2").arg(name).arg(addr, 0, 16));
    --navDepth;
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
    currentAddr_ = addr;

    ghidra::Address address = program_->getAddressFactory()->oldGetAddressFromLong(addr);
    auto* funcMgr = program_->getFunctionManager();
    currentFunction_ = funcMgr ? funcMgr->getFunctionAt(address) : nullptr;

    QString name;
    if (currentFunction_) {
        name = QString::fromStdString(currentFunction_->getName());
        NAVLOG("function='%s'\n", name.toStdString().c_str());
    } else {
        auto syms = program_->getSymbolTable()->getSymbols(address);
        if (!syms.empty() && syms[0]) name = QString::fromStdString(syms[0]->getName());
        NAVLOG("no function, symbol='%s'\n", name.toStdString().c_str());
    }
    if (name.isEmpty()) name = QString("0x%1").arg(addr, 0, 16);

    statusFunc_->setText(name);
    statusAddr_->setText(QString("0x%1").arg(addr, 0, 16));
    disasmDock_->raise();

    NAVLOG("disassembleAt...\n");
    QString asmText = QString::fromStdString(
        decompInterface_->disassembleAt(address, 50));
    disasmView_->showDisassembly(asmText);

    NAVLOG("decompile...\n");
    auto it = decompCache_.find(addr);
    if (it != decompCache_.end()) {
        decompView_->showDecompiled(it->second.cCode, addr,
            it->second.markupXml, it->second.opAddresses);
    } else {
        auto results = decompInterface_->decompileFunction(address, nullptr);
        if (results.decompiled) {
            QString cCode = QString::fromStdString(results.cCode);
            DecompCacheEntry entry;
            entry.cCode = cCode;
            entry.markupXml = QString::fromStdString(results.markupXml);
            entry.opAddresses = results.opAddresses;
            decompCache_[addr] = entry;
            decompView_->showDecompiled(cCode, addr,
                entry.markupXml, entry.opAddresses);
        } else {
            decompView_->clear();
        }
    }

    NAVLOG("hex view...\n");
    std::vector<uint8_t> bytes(256);
    int got = program_->getMemory()->getBytes(address, bytes.data(), 256);
    if (got > 0) {
        bytes.resize(got);
        hexView_->setData(addr, bytes);
    } else {
        hexView_->clear();
    }
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
        if (hexView_->containsAddress(addr)) {
            hexView_->seek(addr);
        } else {
            auto* af = program_->getAddressFactory();
            auto* mem = program_->getMemory();
            if (af && mem) {
                ghidra::Address a = af->oldGetAddressFromLong(addr);
                std::vector<uint8_t> bytes(256);
                int got = mem->getBytes(a, bytes.data(), 256);
                if (got > 0) {
                    bytes.resize(got);
                    hexView_->setData(addr, bytes);
                }
            }
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

void MainWindow::onUndo() {}
void MainWindow::onRedo() {}
void MainWindow::onRenameFunction() {}
void MainWindow::onDeleteFunction() {}
void MainWindow::onAddLabel() {}
void MainWindow::onRemoveLabel() {}
void MainWindow::onSetComment() {}
void MainWindow::onRemoveComment() {}
void MainWindow::onAddBookmark() {}
void MainWindow::onDeleteBookmark() {}
void MainWindow::executeWithEvent(std::unique_ptr<ghidra::storage::Event> event) {}
void MainWindow::updateUndoRedoActions() {}
