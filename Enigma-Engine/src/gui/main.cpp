#include <QApplication>
#include <QStyleFactory>
#include "MainWindow.h"
#include <ghidra/DecompInterface.h>

int main(int argc, char** argv) {
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
    return ret;
}
