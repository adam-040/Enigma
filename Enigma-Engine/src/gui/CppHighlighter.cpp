#include "CppHighlighter.h"
#include <QFont>

CppHighlighter::CppHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent)
{
    QTextCharFormat keyword;
    keyword.setForeground(QColor(0x00, 0x00, 0xff));
    keyword.setFontWeight(QFont::Bold);

    QStringList keywords = {
        "auto", "break", "case", "char", "const", "continue", "default",
        "do", "double", "else", "enum", "extern", "float", "for", "goto",
        "if", "int", "long", "register", "return", "short", "signed",
        "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while", "bool", "true", "false",
        "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
        "uint32_t", "uint64_t", "size_t",
        "__stdcall", "__cdecl", "__fastcall", "__thiscall", "__vectorcall"
    };

    for (const auto& k : keywords) {
        Rule r;
        r.pattern = QRegularExpression("\\b" + k + "\\b");
        r.format = keyword;
        rules_.push_back(r);
    }

    QTextCharFormat number;
    number.setForeground(QColor(0xb8, 0x4e, 0x4e));
    rules_.push_back({ QRegularExpression("\\b[0-9]+[uUlLxXa-fA-F]*\\b"), number });
    rules_.push_back({ QRegularExpression("0[xX][0-9a-fA-F]+"), number });

    QTextCharFormat decType;
    decType.setForeground(QColor(0x0e, 0x8a, 0x8a));
    decType.setFontWeight(QFont::Bold);
    rules_.push_back({ QRegularExpression("\\b(int[1248]|uint[1248]|float[48]|float16|bool4|code|void)\\b"), decType });

    QTextCharFormat decFunc;
    decFunc.setForeground(QColor(0x6f, 0x42, 0xc1));
    rules_.push_back({ QRegularExpression("\\b(func|thunk|code|entry)_0x[0-9a-fA-F]+\\b"), decFunc });

    QTextCharFormat decVar;
    decVar.setForeground(QColor(0x6f, 0x42, 0xc1));
    rules_.push_back({ QRegularExpression("\\b(local|ptr|data|label|unk|ext|off|ord)_0x[0-9a-fA-F]+\\b"), decVar });
    rules_.push_back({ QRegularExpression("\\bparam_[0-9]+\\b"), decVar });
    rules_.push_back({ QRegularExpression("\\bv_[0-9]+\\b"), decVar });

    QTextCharFormat decReg;
    decReg.setForeground(QColor(0x00, 0x70, 0xc0));
    rules_.push_back({ QRegularExpression("\\b(arg_|out_)[a-z0-9]+\\b"), decReg });
    rules_.push_back({ QRegularExpression("\\b(unaff)_0x[0-9a-fA-F]+\\b"), decReg });

    QTextCharFormat comment;
    comment.setForeground(QColor(0x6a, 0x99, 0x55));
    comment.setFontItalic(true);
    rules_.push_back({ QRegularExpression("//[^\n]*"), comment });
    rules_.push_back({ QRegularExpression("/\\*.*\\*/"), comment });

    QTextCharFormat string;
    string.setForeground(QColor(0xa3, 0x15, 0x15));
    rules_.push_back({ QRegularExpression("\"[^\"]*\""), string });
    rules_.push_back({ QRegularExpression("'[^']*'"), string });
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
