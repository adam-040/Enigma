#pragma once

#include "FieldView.h"
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

class DecompilerView : public FieldView {
    Q_OBJECT
public:
    explicit DecompilerView(QWidget* parent = nullptr);
    void showDecompiled(const QString& text, uint64_t funcAddr = 0);
    void showDecompiled(const QString& text, uint64_t funcAddr,
                        const QString& markupXml,
                        const std::vector<std::pair<uint64_t, uint64_t>>& opAddresses);
    void clear();

signals:
    void addressDoubleClicked(uint64_t addr);

private:
    std::vector<Token> tokenizeCLine(const QString& line);
    std::unique_ptr<Document> documentFromMarkup(
        const QString& markupXml,
        uint64_t funcAddr,
        const std::vector<std::pair<uint64_t, uint64_t>>& opAddresses) const;
    static TokenKind classifyCWord(const QString& id);

    QString lastText_;
};
