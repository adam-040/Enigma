#pragma once

#include "FieldView.h"
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace ghidra {
class ProgramDB;
}

class DecompilerView : public FieldView {
    Q_OBJECT
public:
    explicit DecompilerView(QWidget* parent = nullptr);
    void showDecompiled(const QString& text, uint64_t funcAddr = 0);
    void showDecompiled(const QString& text, uint64_t funcAddr,
                        const QString& markupXml,
                        const std::vector<std::pair<uint64_t, uint64_t>>& opAddresses);
    void clear();
    void setProgram(ghidra::ProgramDB* program) { program_ = program; }

signals:
    void addressDoubleClicked(uint64_t addr);

private:
    QColor colorForKind(TokenKind kind) const override;
    bool isBoldKind(TokenKind kind) const override;
    std::vector<Token> tokenizeCLine(const QString& line, int& braceDepth, int& parenDepth);
    std::unique_ptr<Document> documentFromMarkup(
        const QString& markupXml,
        uint64_t funcAddr,
        const std::vector<std::pair<uint64_t, uint64_t>>& opAddresses) const;
    static TokenKind classifyCWord(const QString& id);

    // String-injection helpers: resolve (char *)0xHEX cast pointers against
    // program memory into C string literals ("password: " instead of 0x404000).
    QString readStringAt(uint64_t addr) const;
    bool tryResolveStringToken(const QVector<Token>& history, Token& t) const;

    QString lastText_;
    ghidra::ProgramDB* program_ = nullptr;
};
