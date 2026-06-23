#include <QApplication>
#include <QStyleFactory>
#include <QMessageLogContext>
#include <QDebug>
#include "MainWindow.h"
#include <ghidra/DecompInterface.h>
#include <windows.h>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <exception>

// ── Crash logging infrastructure ─────────────────────────────────────────

static FILE* g_crashLog = nullptr;
static FILE* crashLog() {
    if (!g_crashLog) {
        g_crashLog = fopen("C:\\Users\\pc\\Desktop\\enigma_gui_crash.log", "a");
    }
    return g_crashLog;
}

#define CRASHLOG(...) do { FILE* _f = crashLog(); if (_f) { fprintf(_f, __VA_ARGS__); fflush(_f); } } while(0)

static void printStack() {
    void* stack[64];
    USHORT frames = CaptureStackBackTrace(1, 64, stack, NULL);
    CRASHLOG("  Stack (%d frames):\n", frames);
    for (USHORT i = 0; i < frames; ++i) {
        CRASHLOG("    #%d: 0x%p\n", i, stack[i]);
    }
}

static LONG WINAPI sehHandler(EXCEPTION_POINTERS* ep) {
    CRASHLOG("\n=== UNHANDLED SEH EXCEPTION ===\n");
    CRASHLOG("ExceptionCode: 0x%08X\n", ep->ExceptionRecord->ExceptionCode);
    CRASHLOG("ExceptionFlags: 0x%X\n", ep->ExceptionRecord->ExceptionFlags);
    CRASHLOG("ExceptionAddress: 0x%p\n", ep->ExceptionRecord->ExceptionAddress);
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        CRASHLOG("AccessViolation: %s at 0x%p\n",
            ep->ExceptionRecord->ExceptionInformation[0] ? "write" : "read",
            (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    }
    printStack();
    CRASHLOG("=== END SEH ===\n\n");
    fclose(g_crashLog);
    g_crashLog = nullptr;
    return EXCEPTION_CONTINUE_SEARCH; // Let Windows show the error dialog
}

static void signalHandler(int sig) {
    CRASHLOG("\n=== SIGNAL %d ===\n", sig);
    printStack();
    CRASHLOG("=== END SIGNAL ===\n\n");
    fclose(g_crashLog);
    g_crashLog = nullptr;
    std::_Exit(EXIT_FAILURE);
}

static void terminateHandler() {
    CRASHLOG("\n=== UNHANDLED C++ EXCEPTION (terminate) ===\n");
    if (std::current_exception()) {
        try { throw; }
        catch (const std::exception& e) {
            CRASHLOG("what(): %s\n", e.what());
        }
        catch (...) {
            CRASHLOG("unknown exception type\n");
        }
    }
    printStack();
    CRASHLOG("=== END TERMINATE ===\n\n");
    fclose(g_crashLog);
    g_crashLog = nullptr;
    std::_Exit(EXIT_FAILURE);
}

static void purecallHandler() {
    CRASHLOG("\n=== PURE VIRTUAL FUNCTION CALL ===\n");
    printStack();
    CRASHLOG("=== END PURE ===\n\n");
    fclose(g_crashLog);
    g_crashLog = nullptr;
    std::_Exit(EXIT_FAILURE);
}

static void qtMessageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg) {
    const char* level = "";
    switch (type) {
    case QtDebugMsg:    level = "DEBUG";    break;
    case QtInfoMsg:     level = "INFO";     break;
    case QtWarningMsg:  level = "WARN";     break;
    case QtCriticalMsg: level = "CRITICAL"; break;
    case QtFatalMsg:    level = "FATAL";    break;
    }
    CRASHLOG("[QT-%s] %s (%s:%d)\n", level, msg.toStdString().c_str(),
        ctx.file ? ctx.file : "?", ctx.line);
    if (type == QtFatalMsg) {
        printStack();
        fclose(g_crashLog);
        g_crashLog = nullptr;
    }
}

static void installCrashHandlers() {
    CRASHLOG("=== ENIGMA ENGINE START ===\n");
    CRASHLOG("PID: %lu\n", GetCurrentProcessId());
    SYSTEM_INFO si; GetSystemInfo(&si);
    CRASHLOG("PageSize: %lu, MinAddr: %p, MaxAddr: %p\n",
        si.dwPageSize, si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress);
    CRASHLOG("\n");

    SetUnhandledExceptionFilter(sehHandler);
    signal(SIGABRT, signalHandler);
    signal(SIGSEGV, signalHandler);
    signal(SIGFPE, signalHandler);
    signal(SIGILL, signalHandler);
    std::set_terminate(terminateHandler);
#ifdef _MSC_VER
    _set_purecall_handler(purecallHandler);
#endif
    qInstallMessageHandler(qtMessageHandler);
}

// ── Main ─────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    installCrashHandlers();

    QApplication app(argc, argv);
    app.setApplicationName("Enigma Engine");
    app.setOrganizationName("Enigma");

    if (!ghidra::DecompInterface::initializeLibrary()) {
        return 1;
    }

    MainWindow w;
    w.setWindowTitle("Enigma Engine");
    w.resize(1400, 850);
    w.show();

    // Command-line: first arg is binary path to auto-load for debugging
    if (argc > 1) {
        QMetaObject::invokeMethod(&w, [&w, argv]() {
            w.loadBinary(QString::fromUtf8(argv[1]));
        }, Qt::QueuedConnection);
    }

    int ret = app.exec();
    ghidra::DecompInterface::shutdownLibrary();
    CRASHLOG("=== ENIGMA ENGINE EXIT (code=%d) ===\n", ret);
    fclose(g_crashLog);
    g_crashLog = nullptr;
    return ret;
}
