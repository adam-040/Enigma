#include "DecompilerView.h"
#include <QXmlStreamReader>
#include <QSet>
#include <unordered_map>

DecompilerView::DecompilerView(QWidget* parent)
    : FieldView(parent)
{
}

// ── C keyword / type classification ──────────────────────────────────────────

static const QSet<QString>& cKeywords() {
    static const QSet<QString> kw {
        "if", "else", "while", "for", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", "sizeof", "typedef",
        "struct", "union", "enum", "const", "static", "extern", "volatile",
        "register", "inline", "auto", "restrict",
        "__stdcall", "__cdecl", "__fastcall", "__thiscall",
        "true", "false", "nullptr", "NULL",
    };
    return kw;
}

static const QSet<QString>& cTypes() {
    static const QSet<QString> ty {
        "void", "int", "char", "short", "long", "float", "double",
        "unsigned", "signed", "bool",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t",
        "size_t", "ssize_t", "ptrdiff_t", "uintptr_t", "intptr_t",
        "BYTE", "WORD", "DWORD", "QWORD", "BOOL", "HANDLE",
        "LPVOID", "LPCSTR", "LPSTR", "HRESULT",
        "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
        "byte", "ushort", "uint", "ulong", "longlong", "ulonglong",
        "code", "pointer",
    };
    return ty;
}

TokenKind DecompilerView::classifyCWord(const QString& id) {
    if (cTypes().contains(id))    return TokenKind::Type;
    if (cKeywords().contains(id)) return TokenKind::Keyword;
    return TokenKind::Plain;
}

// ── Simple C tokenizer ───────────────────────────────────────────────────────

std::vector<Token> DecompilerView::tokenizeCLine(const QString& line) {
    std::vector<Token> result;
    const int n = line.size();
    int i = 0;

    while (i < n) {
        QChar c = line[i];

        // ── whitespace → spaceAfter on previous token ──
        if (c.isSpace()) {
            int start = i;
            while (i < n && line[i].isSpace()) ++i;
            if (!result.empty())
                result.back().spaceAfter += (i - start);
            else {
                // leading indent: create a dummy empty token to carry it
                Token pad;
                pad.text = QString();
                pad.kind = TokenKind::Plain;
                pad.spaceAfter = i - start;
                result.push_back(pad);
            }
            continue;
        }

        // ── line comment  // ... ──
        if (c == '/' && i + 1 < n && line[i + 1] == '/') {
            Token t; t.text = line.mid(i); t.kind = TokenKind::Comment;
            result.push_back(t);
            break;
        }

        // ── block comment  /* ... */ (within one line) ──
        if (c == '/' && i + 1 < n && line[i + 1] == '*') {
            int end = line.indexOf(QStringLiteral("*/"), i + 2);
            if (end >= 0) {
                Token t; t.text = line.mid(i, end + 2 - i); t.kind = TokenKind::Comment;
                result.push_back(t);
                i = end + 2;
            } else {
                Token t; t.text = line.mid(i); t.kind = TokenKind::Comment;
                result.push_back(t);
                break;
            }
            continue;
        }

        // ── string literal "..." ──
        if (c == '"') {
            int j = i + 1;
            while (j < n && line[j] != '"') {
                if (line[j] == '\\' && j + 1 < n) j += 2; else ++j;
            }
            if (j < n) ++j;
            Token t; t.text = line.mid(i, j - i); t.kind = TokenKind::String;
            result.push_back(t);
            i = j;
            continue;
        }

        // ── char literal '...' ──
        if (c == '\'') {
            int j = i + 1;
            while (j < n && line[j] != '\'') {
                if (line[j] == '\\' && j + 1 < n) j += 2; else ++j;
            }
            if (j < n) ++j;
            Token t; t.text = line.mid(i, j - i); t.kind = TokenKind::String;
            result.push_back(t);
            i = j;
            continue;
        }

        // ── hex number 0x... ──
        if (c == '0' && i + 1 < n && (line[i + 1] == 'x' || line[i + 1] == 'X')) {
            int j = i + 2;
            while (j < n && (line[j].isDigit() ||
                   (line[j] >= 'a' && line[j] <= 'f') ||
                   (line[j] >= 'A' && line[j] <= 'F'))) ++j;
            QString txt = line.mid(i, j - i);
            Token t;
            t.text = txt;
            t.kind = TokenKind::Immediate;
            bool ok = false;
            uint64_t val = txt.mid(2).toULongLong(&ok, 16);
            if (ok && val > 0x1000) t.refTarget = val;
            result.push_back(t);
            i = j;
            continue;
        }

        // ── decimal number ──
        if (c.isDigit()) {
            int j = i;
            while (j < n && (line[j].isDigit() || line[j] == 'U' || line[j] == 'L' ||
                   line[j] == 'u' || line[j] == 'l')) ++j;
            Token t; t.text = line.mid(i, j - i); t.kind = TokenKind::Number;
            result.push_back(t);
            i = j;
            continue;
        }

        // ── identifier / keyword / type ──
        if (c.isLetter() || c == '_') {
            int j = i;
            while (j < n && (line[j].isLetterOrNumber() || line[j] == '_')) ++j;
            QString id = line.mid(i, j - i);
            Token t; t.text = id; t.kind = classifyCWord(id);
            result.push_back(t);
            i = j;
            continue;
        }

        // ── multi-char operators ──
        if (i + 1 < n) {
            QString two = line.mid(i, 2);
            if (two == QStringLiteral("->") || two == QStringLiteral("::") ||
                two == QStringLiteral("==") || two == QStringLiteral("!=") ||
                two == QStringLiteral("<=") || two == QStringLiteral(">=") ||
                two == QStringLiteral("&&") || two == QStringLiteral("||") ||
                two == QStringLiteral("<<") || two == QStringLiteral(">>") ||
                two == QStringLiteral("+=") || two == QStringLiteral("-=") ||
                two == QStringLiteral("*=") || two == QStringLiteral("/=")) {
                Token t; t.text = two; t.kind = TokenKind::Punctuation;
                result.push_back(t);
                i += 2;
                continue;
            }
        }

        // ── single-char punctuation / operator ──
        {
            Token t; t.text = line.mid(i, 1); t.kind = TokenKind::Punctuation;
            result.push_back(t);
            ++i;
        }
    }

    return result;
}

// ── Public API ───────────────────────────────────────────────────────────────

static TokenKind kindForMarkupElement(const QString& name, const QString& content) {
    if (name == QStringLiteral("variable")) return TokenKind::Variable;
    if (name == QStringLiteral("funcname")) return TokenKind::Function;
    if (name == QStringLiteral("type")) return TokenKind::Type;
    if (name == QStringLiteral("comment")) return TokenKind::Comment;
    if (name == QStringLiteral("label")) return TokenKind::Label;
    if (name == QStringLiteral("field")) return TokenKind::Variable;
    if (name == QStringLiteral("value")) return TokenKind::Immediate;
    if (name == QStringLiteral("op")) return TokenKind::Punctuation;
    if (name == QStringLiteral("syntax"))
        return content.trimmed().isEmpty() ? TokenKind::Plain : TokenKind::Punctuation;
    return TokenKind::Plain;
}

std::unique_ptr<Document> DecompilerView::documentFromMarkup(
    const QString& markupXml,
    uint64_t funcAddr,
    const std::vector<std::pair<uint64_t, uint64_t>>& opAddresses) const
{
    if (markupXml.trimmed().isEmpty())
        return nullptr;

    std::unordered_map<uint64_t, uint64_t> opToAddr;
    for (const auto& p : opAddresses)
        opToAddr[p.first] = p.second;

    auto doc = std::make_unique<Document>();
    QXmlStreamReader xml(markupXml);
    Line line;
    line.addr = funcAddr;
    uint64_t statementAddr = funcAddr;

    auto flushLine = [&]() {
        doc->addLine(std::move(line));
        line = Line{};
        line.addr = statementAddr != 0 ? statementAddr : funcAddr;
    };

    auto attrULL = [](const QXmlStreamAttributes& attrs, const QString& name, bool* okOut = nullptr) -> uint64_t {
        bool ok = false;
        uint64_t value = attrs.value(name).toULongLong(&ok, 0);
        if (okOut) *okOut = ok;
        return ok ? value : 0;
    };

    while (!xml.atEnd()) {
        xml.readNext();
        if (!xml.isStartElement())
            continue;

        const QString name = xml.name().toString();
        const auto attrs = xml.attributes();

        bool opOk = false;
        uint64_t opref = attrULL(attrs, QStringLiteral("opref"), &opOk);
        uint64_t tokenAddr = 0;
        if (opOk) {
            auto it = opToAddr.find(opref);
            if (it != opToAddr.end())
                tokenAddr = it->second;
        }

        if (name == QStringLiteral("statement")) {
            if (tokenAddr != 0) {
                statementAddr = tokenAddr;
                if (line.tokens.isEmpty())
                    line.addr = statementAddr;
            }
            continue;
        }

        if (name == QStringLiteral("break")) {
            int indent = attrs.value(QStringLiteral("indent")).toInt();
            flushLine();
            if (indent > 0) {
                Token pad;
                pad.spaceAfter = indent;
                pad.addr = line.addr;
                line.tokens.push_back(pad);
            }
            continue;
        }

        if (name == QStringLiteral("label") || name == QStringLiteral("comment")) {
            bool offOk = false;
            uint64_t off = attrULL(attrs, QStringLiteral("off"), &offOk);
            if (offOk && off != 0)
                tokenAddr = off;
        }

        if (name != QStringLiteral("variable") &&
            name != QStringLiteral("op") &&
            name != QStringLiteral("funcname") &&
            name != QStringLiteral("type") &&
            name != QStringLiteral("field") &&
            name != QStringLiteral("value") &&
            name != QStringLiteral("comment") &&
            name != QStringLiteral("label") &&
            name != QStringLiteral("syntax")) {
            continue;
        }

        const QString content = attrs.value(QStringLiteral("content")).toString();
        if (content.isEmpty())
            continue;

        if (content.trimmed().isEmpty()) {
            if (!line.tokens.isEmpty())
                line.tokens.back().spaceAfter += content.size();
            else {
                Token pad;
                pad.spaceAfter = content.size();
                pad.addr = line.addr;
                line.tokens.push_back(pad);
            }
            continue;
        }

        const QStringList parts = content.split(QLatin1Char('\n'));
        for (int i = 0; i < parts.size(); ++i) {
            if (i > 0)
                flushLine();
            if (parts[i].isEmpty())
                continue;
            Token t;
            t.text = parts[i];
            t.kind = kindForMarkupElement(name, parts[i]);
            t.addr = tokenAddr != 0 ? tokenAddr : (statementAddr != 0 ? statementAddr : funcAddr);
            if (line.addr == 0)
                line.addr = t.addr;
            line.tokens.push_back(t);
        }
    }

    if (xml.hasError() || doc->lineCount() == 0 && line.tokens.isEmpty())
        return nullptr;

    if (!line.tokens.isEmpty())
        doc->addLine(std::move(line));
    doc->finalize();
    return doc;
}

void DecompilerView::showDecompiled(const QString& text, uint64_t funcAddr) {
    lastText_ = text;
    auto doc = std::make_unique<Document>();

    const QStringList rawLines = text.split('\n');

    for (const QString& raw : rawLines) {
        Line l;
        l.addr = funcAddr;   // all lines map to the function entry

        if (raw.trimmed().isEmpty()) {
            // Preserve blank lines for readability
            doc->addLine(std::move(l));
            continue;
        }

        auto tokens = tokenizeCLine(raw);
        for (auto& t : tokens) {
            t.addr = funcAddr;
            l.tokens.push_back(t);
        }

        doc->addLine(std::move(l));
    }

    doc->finalize();
    setDocument(std::move(doc));
}

void DecompilerView::showDecompiled(
    const QString& text,
    uint64_t funcAddr,
    const QString& markupXml,
    const std::vector<std::pair<uint64_t, uint64_t>>& opAddresses)
{
    lastText_ = text;
    auto doc = documentFromMarkup(markupXml, funcAddr, opAddresses);
    if (doc) {
        setDocument(std::move(doc));
        return;
    }
    showDecompiled(text, funcAddr);
}

void DecompilerView::clear() {
    clearDocument();
}
