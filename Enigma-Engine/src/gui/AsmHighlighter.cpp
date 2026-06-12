#include "AsmHighlighter.h"
#include <QFont>

AsmHighlighter::AsmHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent)
{
    QTextCharFormat comment;
    comment.setForeground(QColor(0x6a, 0x99, 0x5f));
    comment.setFontItalic(true);
    rules_.push_back({ QRegularExpression(";[^\n]*"), comment });
    rules_.push_back({ QRegularExpression("//[^\n]*"), comment });

    QTextCharFormat address;
    address.setForeground(QColor(0x88, 0x88, 0x88));
    rules_.push_back({ QRegularExpression("0x[0-9a-fA-F]+"), address });

    QTextCharFormat mnemonic;
    mnemonic.setForeground(QColor(0x56, 0x9c, 0xd6));
    mnemonic.setFontWeight(QFont::Bold);
    rules_.push_back({ QRegularExpression("\\b[a-z]{2,6}\\b"), mnemonic });

    QTextCharFormat label;
    label.setForeground(QColor(0xd0, 0xd0, 0xd0));
    label.setFontWeight(QFont::Bold);
    rules_.push_back({ QRegularExpression("^[a-zA-Z_][a-zA-Z0-9_]*:"), label });

    QTextCharFormat number;
    number.setForeground(QColor(0xb5, 0xce, 0xa8));
    rules_.push_back({ QRegularExpression("\\b[0-9]+\\b"), number });

    QTextCharFormat string;
    string.setForeground(QColor(0xce, 0x91, 0x78));
    rules_.push_back({ QRegularExpression("\"[^\"]*\""), string });

    QTextCharFormat register_;
    register_.setForeground(QColor(0xd0, 0x70, 0x70));
    rules_.push_back({ QRegularExpression("\\b(e?[a-d][xhl]|[sd]i|[bs]p|r[0-9]+d?|xmm[0-9]+)\\b"), register_ });
}

void AsmHighlighter::highlightBlock(const QString& text) {
    for (const auto& rule : rules_) {
        auto it = rule.pattern.globalMatch(text);
        while (it.hasNext()) {
            auto match = it.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);
        }
    }
}
