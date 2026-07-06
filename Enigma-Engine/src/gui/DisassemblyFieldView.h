#pragma once

#include "FieldView.h"
#include <QRegularExpression>
#include <QStringList>
#include <cstdint>
#include <vector>

namespace ghidra {
class ProgramDB;
class DecompInterface;
}

class DisassemblyFieldView : public FieldView {
    Q_OBJECT
public:
    explicit DisassemblyFieldView(QWidget* parent = nullptr);
    void showDisassembly(const QString& text);
    void setProgram(ghidra::ProgramDB* program);
    void setDecompInterface(ghidra::DecompInterface* decomp);
    void setShowBytes(bool show);
    bool showBytes() const;

    void buildFullIndex();
    void seekToAddress(uint64_t addr);
    int totalInstructions() const { return indexBuilt_ ? 1 : 0; }

signals:
    void addressJumpRequested(uint64_t addr);

private:
    struct ParsedLine {
        uint64_t addr = 0;
        QString mne;
        QString body;
    };

    void buildDocumentFromParsed();

    std::vector<Token> tokenizeOperands(const QString& ops, uint64_t lineAddr);
    TokenKind classifyIdentifier(const QString& id) const;
    static bool isBranchMnemonic(const QString& mne);
    static QString formatBytes(const std::vector<uint8_t>& bytes);

    ghidra::ProgramDB* program_ = nullptr;
    ghidra::DecompInterface* decomp_ = nullptr;
    bool showBytes_ = false;
    QString lastText_;
    std::vector<ParsedLine> parsed_;

    bool indexBuilt_ = false;
};
