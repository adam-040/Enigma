#include "CppHighlighter.h"
#include <QFont>

CppHighlighter::CppHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent)
{
    QTextCharFormat keyword;
    keyword.setForeground(QColor(0x56, 0x9c, 0xd6));
    keyword.setFontWeight(QFont::Bold);

    QStringList keywords = {
        "auto", "break", "case", "char", "const", "continue", "default",
        "do", "double", "else", "enum", "extern", "float", "for", "goto",
        "if", "int", "long", "register", "return", "short", "signed",
        "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while", "bool", "true", "false",
        "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
        "uint32_t", "uint64_t", "size_t"
    };

    for (const auto& k : keywords) {
        Rule r;
        r.pattern = QRegularExpression("\\b" + k + "\\b");
        r.format = keyword;
        rules_.push_back(r);
    }

    QTextCharFormat number;
    number.setForeground(QColor(0xb5, 0xce, 0xa8));
    rules_.push_back({ QRegularExpression("\\b[0-9]+[uUlLxXa-fA-F]*\\b"), number });
    rules_.push_back({ QRegularExpression("0[xX][0-9a-fA-F]+"), number });

    QTextCharFormat comment;
    comment.setForeground(QColor(0x6a, 0x99, 0x5f));
    comment.setFontItalic(true);
    rules_.push_back({ QRegularExpression("//[^\n]*"), comment });
    rules_.push_back({ QRegularExpression("/\\*.*\\*/"), comment });

    QTextCharFormat string;
    string.setForeground(QColor(0xce, 0x91, 0x78));
    rules_.push_back({ QRegularExpression("\"[^\"]*\""), string });
    rules_.push_back({ QRegularExpression("'[^']*'"), string });

    QTextCharFormat preprocessor;
    preprocessor.setForeground(QColor(0x9b, 0x9b, 0x9b));
    rules_.push_back({ QRegularExpression("#[^\n]*"), preprocessor });
}

void CppHighlighter::highlightBlock(const QString& text) {
    for (const auto& rule : rules_) {
        auto it = rule.pattern.globalMatch(text);
        while (it.hasNext()) {
            auto match = it.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);
        }
    }
}
