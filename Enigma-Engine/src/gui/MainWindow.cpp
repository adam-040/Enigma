#include "MainWindow.h"
#include "FunctionExplorer.h"
#include "DisassemblyView.h"
#include "DecompilerView.h"
#include "HexView.h"
#include "ConsoleWidget.h"

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


MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setDockOptions(QMainWindow::AllowNestedDocks |
                   QMainWindow::AllowTabbedDocks |
                   QMainWindow::GroupedDragging);

    createMenuBar();
    createDockWidgets();
    createStatusBar();

    setCentralWidget(new QWidget(this));
    centralWidget()->hide();

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
    view->addAction(tr("&Disassembly"));
    view->addAction(tr("&Decompiler"));
    view->addAction(tr("&Hex"));

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

    menuBar()->addMenu(tr("&Repository"));
    menuBar()->addMenu(tr("&Tools"));
    menuBar()->addMenu(tr("&Help"));
}

void MainWindow::createDockWidgets() {
    disasmView_ = new DisassemblyView(this);
    decompView_ = new DecompilerView(this);
    hexView_ = new HexView(this);
    console_ = new ConsoleWidget(this);
    explorer_ = new FunctionExplorer(this);

    auto createDock = [&](const QString& title, QWidget* widget) -> QDockWidget* {
        auto* dock = new QDockWidget(title, this);
        dock->setObjectName(title);
        dock->setWidget(widget);
        dock->setFeatures(QDockWidget::DockWidgetMovable |
                          QDockWidget::DockWidgetClosable |
                          QDockWidget::DockWidgetFloatable);
        dock->setAllowedAreas(Qt::AllDockWidgetAreas);
        return dock;
    };

    explorerDock_ = createDock("EXPLORER", explorer_);
    disasmDock_   = createDock("DISASSEMBLY", disasmView_);
    decompDock_   = createDock("DECOMPILER", decompView_);
    hexDock_      = createDock("HEX", hexView_);
    consoleDock_  = createDock("CONSOLE", console_);

    addDockWidget(Qt::LeftDockWidgetArea, explorerDock_);
    addDockWidget(Qt::RightDockWidgetArea, disasmDock_);
    splitDockWidget(disasmDock_, decompDock_, Qt::Vertical);
    splitDockWidget(decompDock_, hexDock_, Qt::Vertical);
    addDockWidget(Qt::BottomDockWidgetArea, consoleDock_);

    connect(explorer_, &FunctionExplorer::functionSelected,
            this, &MainWindow::onFunctionSelected);
    connect(disasmView_, &DisassemblyView::addressDoubleClicked,
            this, &MainWindow::onDisasmAddressDoubleClicked);
    connect(decompView_, &DecompilerView::addressDoubleClicked,
            this, &MainWindow::onDecompAddressDoubleClicked);
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
static FILE* logFile() {
    if (!g_log) {
        const char* envPath = getenv("DBG_LOG");
        const char* path = envPath ? envPath : "C:\\Users\\pc\\Desktop\\enigma_gui_debug.log";
        g_log = fopen(path, "w");
    }
    return g_log;
}
#define DBG(...) do { FILE* _dbf = logFile(); if(_dbf){fprintf(_dbf, __VA_ARGS__);fflush(_dbf);} } while(0)

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
    console_->log("Project saved to: " + dir);
}

void MainWindow::onOpenProject() {
    QString dir = QFileDialog::getExistingDirectory(this, tr("Open Project"));
    if (dir.isEmpty()) return;
    console_->log("Project loaded from: " + dir);
}

void MainWindow::loadBinary(const QString& path) {
    DBG("[loadBinary] START\n");
    console_->log("> Loading: " + path);
    QApplication::processEvents();

    auto loader = ghidra::createLoader();
    if (!loader) { DBG("[loadBinary] createLoader returned null\n"); return; }
    DBG("[loadBinary] createLoader OK\n");

    if (!loader->load(path.toStdString())) {
        DBG("[loadBinary] loader->load failed\n");
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

    // VERIFY: ProgramDB pointer identity checkpoint A
    DBG("[loadBinary] PTR-CHECK-A: program_ = %p (will be set to prog = %p)\n", (void*)program_.get(), (void*)prog);

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

    // VERIFY: ProgramDB pointer identity checkpoint B
    DBG("[loadBinary] PTR-CHECK-B: program_ = %p (same as prog = %p)\n", (void*)program_.get(), (void*)prog);
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

    DBG("[loadBinary] calling populateExplorer...\n");
    try {
        populateExplorer();
    } catch (const std::exception& e) {
        DBG("[loadBinary] populateExplorer threw: %s\n", e.what());
        throw;
    }
    DBG("[loadBinary] populateExplorer done\n");

    console_->log(QString("Binary loaded: %1").arg(binaryName));
    console_->log(QString("Architecture: %1-bit %2%3")
        .arg(loader->getBitness())
        .arg(loader->getArchitecture().c_str())
        .arg(loader->isBigEndian() ? " BE" : " LE"));

    DBG("[loadBinary] calling runAnalysisAsync...\n");
    runAnalysisAsync();
    DBG("[loadBinary] END\n");
}

void MainWindow::populateExplorer() {
    explorer_->clear();
    if (!program_) return;

    // VERIFY: ProgramDB pointer identity checkpoint C
    DBG("[populateExplorer] PTR-CHECK-C: program_ = %p\n", (void*)program_.get());

    // DIAGNOSTIC: dump state inside populateExplorer
    {
        auto* fm = program_->getFunctionManager();
        auto* sym = program_->getSymbolTable();
        auto* dtm = program_->getDataTypeManager();
        auto* listing = program_->getListing();
        DBG("[DIAG] EXPLORER-ENTER: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
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
            if (i == 0) DBG("[DIAG]   (no functions in iterator)\n");
        }
    }

    QTreeWidgetItem* root = explorer_->addCategory("Functions");

    auto funcs = decompInterface_->getFunctions();
    DBG("[populateExplorer] decompInterface_->getFunctions() returned %zu entries\n", funcs.size());
    for (auto& f : funcs) {
        uint64_t addr = f.entryAddress.getOffset();
        explorer_->addEntry(root, addr, QString::fromStdString(f.name));
        DBG("[populateExplorer]   addEntry 0x%llx '%s'\n", (unsigned long long)addr, f.name.c_str());
    }

    QString binaryName = QString::fromStdString(program_->getName());
    if (binaryName.isEmpty()) binaryName = "Program";

    auto* funcMgr = program_->getFunctionManager();
    int fmCount = funcMgr ? funcMgr->getFunctionCount() : -1;
    DBG("[populateExplorer] funcMgr->getFunctionCount()=%d  funcs.size()=%zu\n", fmCount, funcs.size());
    if (funcMgr) {
        statusCount_->setText(tr("%1 functions").arg(fmCount));
    } else {
        statusCount_->setText(tr("%1 functions").arg(funcs.size()));
    }
    statusFunc_->setText(binaryName);

    auto* symTable = program_->getSymbolTable();
    if (symTable) {
        auto extPoints = symTable->getExternalEntryPoints();
        if (!extPoints.empty()) {
            QTreeWidgetItem* exportsCat = explorer_->addCategory("Exports");
            for (auto& addr : extPoints) {
                auto syms = symTable->getSymbols(addr);
                QString symName;
                for (auto* s : syms) {
                    if (s) {
                        symName = QString::fromStdString(s->getName());
                        break;
                    }
                }
                if (symName.isEmpty()) symName = QString("sub_%1").arg(addr.getOffset(), 0, 16);
                explorer_->addEntry(exportsCat, addr.getOffset(), symName);
            }
        }
    }

    auto* extMgr = program_->getExternalManager();
    if (extMgr && extMgr->getExternalLocationCount() > 0) {
        QTreeWidgetItem* importsCat = explorer_->addCategory("Imports");
        auto locations = extMgr->getExternalLocations();
        for (auto* loc : locations) {
            if (!loc) continue;
            QString name = QString::fromStdString(loc->getLabel());
            uint64_t addr = loc->getAddress().getOffset();
            explorer_->addEntry(importsCat, addr, name);
        }
    }

    auto* mem = program_->getMemory();
    if (mem) {
        auto blocks = mem->getBlocks();
        if (!blocks.empty()) {
            QTreeWidgetItem* segsCat = explorer_->addCategory("Segments");
            for (auto* block : blocks) {
                if (!block) continue;
                QString name = QString::fromStdString(block->getName());
                uint64_t addr = block->getStart().getOffset();
                explorer_->addEntry(segsCat, addr, name);
            }
        }
    }
}

void MainWindow::runAnalysisAsync() {
    if (!program_) return;
    if (analysisWatcher_.isRunning()) {
        console_->log("Analysis already in progress.");
        return;
    }

    console_->log("> Analysis started...");
    QApplication::processEvents();

    analysisMgr_ = std::make_unique<ghidra::AutoAnalysisManager>(program_.get());
    analysisMgr_->initializeDefaultAnalyzers();

    auto future = QtConcurrent::run([this]() {
        DBG("[analysis worker] START\n");
        if (analysisMgr_) {
            DBG("[analysis worker] calling analyze...\n");
            try {
                // DIAGNOSTIC: dump state just before analyze
                if (program_) {
                    auto* fm = program_->getFunctionManager();
                    auto* sym = program_->getSymbolTable();
                    auto* dtm = program_->getDataTypeManager();
                    auto* listing = program_->getListing();
                    DBG("[DIAG] PRE-ANALYZE: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
                        fm ? fm->getFunctionCount() : -1,
                        sym ? sym->getNumSymbols() : -1,
                        dtm ? dtm->getDataTypeCount(false) : -1,
                        listing ? listing->getDataCount() : 0);
                }
                analysisMgr_->analyze(&ghidra::getDummyMonitor());
                DBG("[analysis worker] analyze completed\n");
                // DIAGNOSTIC: dump state just after analyze
                if (program_) {
                    auto* fm = program_->getFunctionManager();
                    auto* sym = program_->getSymbolTable();
                    auto* dtm = program_->getDataTypeManager();
                    auto* listing = program_->getListing();
                    DBG("[DIAG] POST-ANALYZE: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
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
                        if (i == 0) DBG("[DIAG]   (no functions in iterator)\n");
                    }
                }
            } catch (const std::exception& e) {
                DBG("[analysis worker] analyze threw: %s\n", e.what());
            } catch (...) {
                DBG("[analysis worker] analyze threw unknown\n");
            }
        }
        DBG("[analysis worker] END\n");
    });

    analysisWatcher_.setFuture(future);
    connect(&analysisWatcher_, &QFutureWatcher<void>::finished,
            this, &MainWindow::onAnalysisFinished);
}

void MainWindow::onAnalysisFinished() {
    DBG("[onAnalysisFinished] START\n");
    console_->log("+ Analysis completed.");
    QApplication::processEvents();

    // VERIFY: ProgramDB pointer identity checkpoint D
    DBG("[onAnalysisFinished] PTR-CHECK-D: program_ = %p\n", (void*)program_.get());

    // DIAGNOSTIC: dump state on main thread after analysis
    {
        auto* fm = program_ ? program_->getFunctionManager() : nullptr;
        auto* sym = program_ ? program_->getSymbolTable() : nullptr;
        auto* dtm = program_ ? program_->getDataTypeManager() : nullptr;
        auto* listing = program_ ? program_->getListing() : nullptr;
        DBG("[DIAG] ON-ANALYSIS-FINISHED: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
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
    }

    DBG("[onAnalysisFinished] clearing explorer...\n");
    explorer_->clear();
    DBG("[onAnalysisFinished] re-populating explorer...\n");
    try {
        populateExplorer();
    } catch (const std::exception& e) {
        DBG("[onAnalysisFinished] populateExplorer threw: %s\n", e.what());
        throw;
    }

    if (currentFunction_) {
        DBG("[onAnalysisFinished] navigating to current function\n");
        navigateTo(currentFunction_->getEntryPoint().getOffset(),
                   QString::fromStdString(currentFunction_->getName()));
    } else if (program_) {
        DBG("[onAnalysisFinished] getting functions list...\n");
        auto funcs = decompInterface_->getFunctions();
        if (!funcs.empty()) {
            DBG("[onAnalysisFinished] navigating to first function\n");
            navigateTo(funcs[0].entryAddress.getOffset(),
                       QString::fromStdString(funcs[0].name));
        } else {
            DBG("[onAnalysisFinished] no functions found\n");
        }
    }
    DBG("[onAnalysisFinished] END\n");
}

void MainWindow::onFunctionSelected(uint64_t addr, const QString& name) {
    if (!program_) return;
    navigateTo(addr, name);
}

void MainWindow::navigateTo(uint64_t addr, const QString& name) {
    DBG("[navigateTo] 0x%llx '%s'\n", addr, name.toStdString().c_str());
    if (!program_ || addr == 0) { DBG("[navigateTo] early return\n"); return; }

    // VERIFY: ProgramDB pointer identity checkpoint E
    DBG("[navigateTo] PTR-CHECK-E: program_ = %p\n", (void*)program_.get());

    // DIAGNOSTIC: dump state inside navigateTo
    {
        auto* fm = program_->getFunctionManager();
        auto* sym = program_->getSymbolTable();
        auto* dtm = program_->getDataTypeManager();
        auto* listing = program_->getListing();
        DBG("[DIAG] NAVIGATE-ENTER: funcCount=%d symCount=%d dataTypeCount=%d dataCount=%zu\n",
            fm ? fm->getFunctionCount() : -1,
            sym ? sym->getNumSymbols() : -1,
            dtm ? dtm->getDataTypeCount(false) : -1,
            listing ? listing->getDataCount() : 0);
        if (fm) {
            ghidra::FunctionIterator fit = fm->getFunctions(true);
            int i = 0;
            while (fit.hasNext() && i < 5) {
                auto* f = fit.next();
                if (f) DBG("[DIAG]   fun[%d] = 0x%llx '%s'\n", i,
                    (unsigned long long)f->getEntryPoint().getOffset(), f->getName().c_str());
                i++;
            }
        }
    }

    if (currentAddr_ != 0 && addr != currentAddr_) {
        backStack_.push(currentAddr_);
        forwardStack_.clear();
    }
    currentAddr_ = addr;

    ghidra::Address address = program_->getAddressFactory()->oldGetAddressFromLong(addr);

    auto* funcMgr = program_->getFunctionManager();
    currentFunction_ = funcMgr ? funcMgr->getFunctionAt(address) : nullptr;

    statusFunc_->setText(name);
    statusAddr_->setText(QString("0x%1").arg(addr, 0, 16));

    int instrCount = 30;
    if (currentFunction_) {
        const auto& body = currentFunction_->getBody();
        if (!body.isEmpty())
            instrCount = static_cast<int>(body.getNumAddresses());
    }
    DBG("[navigateTo] address.space='%s' offset=0x%llx\n",
        address.getAddressSpace() ? address.getAddressSpace()->getName().c_str() : "(null)",
        (unsigned long long)address.getOffset());
    // Check if this address is in any memory block
    {
        auto* memCheck = program_->getMemory();
        if (memCheck) {
            try {
                auto* block = memCheck->getBlock(address);
                DBG("[navigateTo]   mem->getBlock = %s\n", block ? block->getName().c_str() : "NULL");
            } catch (...) {
                DBG("[navigateTo]   mem->getBlock threw\n");
            }
        }
    }

    DBG("[navigateTo] disassembleAt(0x%llx, %d)\n", (unsigned long long)addr, instrCount);
    QString asmText = QString::fromStdString(
        decompInterface_->disassembleAt(address, instrCount));
    disasmView_->showDisassembly(asmText);
    DBG("[navigateTo] disassembly done\n");

    auto it = decompCache_.find(addr);
    if (it != decompCache_.end()) {
        decompView_->showDecompiled(it->second);
        DBG("[navigateTo] decompile: cache hit\n");
    } else {
        DBG("[navigateTo] decompileFunction(0x%llx)...\n", addr);
        auto results = decompInterface_->decompileFunction(address, nullptr);
        if (results.decompiled) {
            QString cCode = QString::fromStdString(results.cCode);
            decompCache_[addr] = cCode;
            decompView_->showDecompiled(cCode);
            DBG("[navigateTo] decompile: success (%d bytes)\n", results.cCode.size());
        } else {
            decompView_->clear();
            DBG("[navigateTo] decompile: failed\n");
        }
    }

    DBG("[navigateTo] reading memory bytes...\n");
    std::vector<uint8_t> bytes(256);
    int got = program_->getMemory()->getBytes(address, bytes.data(), 256);
    if (got > 0) {
        bytes.resize(got);
        hexView_->setData(addr, bytes);
    } else {
        hexView_->clear();
    }
    DBG("[navigateTo] hex view updated (%d bytes)\n", got);

    logOnce(QString("Navigated to: %1 @ 0x%2").arg(name).arg(addr, 0, 16));
    DBG("[navigateTo] END\n");
}

void MainWindow::onNavigateBack() {
    if (backStack_.isEmpty() || !program_) return;
    uint64_t addr = backStack_.pop();
    forwardStack_.push(currentAddr_);
    currentAddr_ = addr;

    ghidra::Address address = program_->getAddressFactory()->oldGetAddressFromLong(addr);
    auto* funcMgr = program_->getFunctionManager();
    currentFunction_ = funcMgr ? funcMgr->getFunctionAt(address) : nullptr;

    QString name;
    if (currentFunction_) {
        name = QString::fromStdString(currentFunction_->getName());
    } else {
        auto syms = program_->getSymbolTable()->getSymbols(address);
        if (!syms.empty() && syms[0]) name = QString::fromStdString(syms[0]->getName());
    }
    if (name.isEmpty()) name = QString("0x%1").arg(addr, 0, 16);

    statusFunc_->setText(name);
    statusAddr_->setText(QString("0x%1").arg(addr, 0, 16));
    disasmDock_->raise();

    int instrCount = 30;
    if (currentFunction_) {
        const auto& body = currentFunction_->getBody();
        if (!body.isEmpty())
            instrCount = static_cast<int>(body.getNumAddresses());
    }
    QString asmText = QString::fromStdString(
        decompInterface_->disassembleAt(address, instrCount));
    disasmView_->showDisassembly(asmText);

    auto it = decompCache_.find(addr);
    if (it != decompCache_.end()) {
        decompView_->showDecompiled(it->second);
    } else {
        auto results = decompInterface_->decompileFunction(address, nullptr);
        if (results.decompiled) {
            QString cCode = QString::fromStdString(results.cCode);
            decompCache_[addr] = cCode;
            decompView_->showDecompiled(cCode);
        } else {
            decompView_->clear();
        }
    }

    std::vector<uint8_t> bytes(256);
    int got = program_->getMemory()->getBytes(address, bytes.data(), 256);
    if (got > 0) {
        bytes.resize(got);
        hexView_->setData(addr, bytes);
    } else {
        hexView_->clear();
    }
}

void MainWindow::onNavigateForward() {
    if (forwardStack_.isEmpty() || !program_) return;
    uint64_t addr = forwardStack_.pop();
    backStack_.push(currentAddr_);
    navigateTo(addr, QString());
}

void MainWindow::onDisasmAddressDoubleClicked(uint64_t addr) {
    if (!program_) return;
    QString name;
    auto* funcMgr = program_->getFunctionManager();
    ghidra::Address address = program_->getAddressFactory()->oldGetAddressFromLong(addr);
    auto* func = funcMgr ? funcMgr->getFunctionContaining(address) : nullptr;
    if (func) {
        name = QString::fromStdString(func->getName());
        navigateTo(func->getEntryPoint().getOffset(), name);
    } else {
        auto syms = program_->getSymbolTable()->getSymbols(address);
        if (!syms.empty() && syms[0]) name = QString::fromStdString(syms[0]->getName());
        if (name.isEmpty()) name = QString("0x%1").arg(addr, 0, 16);
        navigateTo(addr, name);
    }
}

void MainWindow::onDecompAddressDoubleClicked(uint64_t addr) {
    onDisasmAddressDoubleClicked(addr);
}

void MainWindow::logOnce(const QString& msg) {
    if (msg != lastConsoleMsg_) {
        console_->log(msg);
        lastConsoleMsg_ = msg;
    }
}
