#include "DecompilerView.h"
#include <QXmlStreamReader>
#include <QSet>
#include <unordered_map>
#include <ghidra/ProgramDB.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>

DecompilerView::DecompilerView(QWidget* parent)
    : FieldView(parent)
{
}

// ── String-injection helpers ────────────────────────────────────────────────
// Mirrors the CLI post-processor (resolveStringRefs in enigma_decompile_full):
// (char *)0xHEX pointer args are read from program memory and rendered as
// C string literals so the decompiler GUI shows "password: " not 0x404000.

QString DecompilerView::readStringAt(uint64_t addr) const {
    if (!program_ || addr == 0) return QString();
    auto* mem = program_->getMemory();
    auto* af = program_->getAddressFactory();
    if (!mem || !af) return QString();
    uint8_t buf[256];
    int got = 0;
    try {
        got = mem->getBytes(af->oldGetAddressFromLong(addr), buf, static_cast<int>(sizeof(buf)));
    } catch (...) { return QString(); }
    if (got <= 0) return QString();

    QString out;
    bool printable = true;
    for (int i = 0; i < got; ++i) {
        uint8_t b = buf[i];
        if (b == 0) break;
        if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') { printable = false; break; }
        out += QChar(static_cast<char>(b));
    }
    if (!printable || out.isEmpty()) return QString();
    return out;
}

bool DecompilerView::tryResolveStringToken(const QVector<Token>& history, Token& t) const {
    if (!program_ || t.text.isEmpty()) return false;

    // Only pure hex literals can be string-pointer candidates.
    bool ok = false;
    uint64_t addr = 0;
    const QString& txt = t.text;
    if (txt.size() > 2 && txt.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        addr = txt.mid(2).toULongLong(&ok, 16);
    if (!ok) return false;

    // Cast-pointer pattern immediately before the literal: ( <type> * ) 0x...
    // Scan backward over padding/empty tokens for ')' then '*' then a type token.
    int j = static_cast<int>(history.size()) - 1;
    while (j >= 0 && history[j].text.isEmpty()) --j;
    if (j < 0 || history[j].text != QLatin1String(")")) return false;
    --j;
    while (j >= 0 && history[j].text.isEmpty()) --j;
    if (j < 0 || history[j].text != QLatin1String("*")) return false;
    --j;
    while (j >= 0 && history[j].text.isEmpty()) --j;
    if (j < 0) return false;
    const QString prev = history[j].text;
    const bool isType = history[j].kind == TokenKind::Type
        || prev == QLatin1String("const")
        || prev.startsWith(QStringLiteral("undefined"));
    if (!isType) return false;

    const QString str = readStringAt(addr);
    if (str.isEmpty()) return false;

    QString quoted = "\"";
    for (const QChar& c : str) {
        char ch = c.toLatin1();
        switch (ch) {
        case '\n': quoted += "\\n"; break;
        case '\r': quoted += "\\r"; break;
        case '\t': quoted += "\\t"; break;
        case '\\': quoted += "\\\\"; break;
        case '"':  quoted += "\\\""; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20)
                quoted += QStringLiteral("\\x%1")
                              .arg(static_cast<unsigned char>(ch), 2, 16, QLatin1Char('0'));
            else
                quoted += c;
        }
    }
    quoted += '"';
    t.text = quoted;
    t.kind = TokenKind::String;
    return true;
}

// ── Decompiler color scheme (balanced to match disassembler aesthetic) ───────

QColor DecompilerView::colorForKind(TokenKind kind) const {
    switch (kind) {
    case TokenKind::Keyword:     return QColor(0x00, 0x00, 0xff); // blue
    case TokenKind::Type:        return QColor(0x0e, 0x8a, 0x8a); // teal
    case TokenKind::Function:    return QColor(0x6f, 0x42, 0xc1); // purple (emphasis, like labels in disasm)
    case TokenKind::String:      return QColor(0xa3, 0x15, 0x15); // dark red
    case TokenKind::Comment:     return QColor(0x6a, 0x99, 0x55); // green
    case TokenKind::Immediate:
    case TokenKind::Number:      return QColor(0xb8, 0x4e, 0x4e); // brown (like immediates in disasm)
    case TokenKind::Register:    return QColor(0x00, 0x70, 0xc0); // blue
    case TokenKind::Punctuation: return QColor(0x80, 0x80, 0x80); // medium gray — easy to track
    default:                     return QColor(0x1e, 0x1e, 0x1e); // dark text (variables, labels)
    }
}

bool DecompilerView::isBoldKind(TokenKind kind) const {
    return kind == TokenKind::Keyword || kind == TokenKind::Type;
}

// ── C keyword / type classification ──────────────────────────────────────────

static const QSet<QString>& cKeywords() {
    static const QSet<QString> kw {
        "if", "else", "while", "for", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", "sizeof", "typedef",
        "struct", "union", "enum", "const", "static", "extern", "volatile",
        "register", "inline", "auto", "restrict",
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
        "int4", "uint4", "int8", "uint8",
        "float4", "float8", "float16", "bool4",
    };
    return ty;
}

// Decompiler-specific identifier prefixes
static TokenKind classifyDecompilerWord(const QString& id) {
    if (id.startsWith(QStringLiteral("func_0x")) ||
        id.startsWith(QStringLiteral("thunk_0x")) ||
        id.startsWith(QStringLiteral("code_0x")) ||
        id.startsWith(QStringLiteral("entry_0x")))
        return TokenKind::Function;

    if (id.startsWith(QStringLiteral("data_0x")) ||
        id.startsWith(QStringLiteral("label_0x")) ||
        id.startsWith(QStringLiteral("unk_0x")) ||
        id.startsWith(QStringLiteral("ext_0x")) ||
        id.startsWith(QStringLiteral("off_0x")) ||
        id.startsWith(QStringLiteral("ord_0x")))
        return TokenKind::Label;

    if (id.startsWith(QStringLiteral("local_0x")) ||
        id.startsWith(QStringLiteral("ptr_0x")))
        return TokenKind::Variable;

    if (id.startsWith(QStringLiteral("param_")))
        return TokenKind::Variable;

    if (id.startsWith(QStringLiteral("arg_")) ||
        id.startsWith(QStringLiteral("out_")) ||
        id.startsWith(QStringLiteral("unaff_")))
        return TokenKind::Register;

    if (id.startsWith(QStringLiteral("v_")) && id.length() > 2) {
        bool ok = false;
        id.mid(2).toInt(&ok);
        if (ok) return TokenKind::Variable;
    }

    return TokenKind::Plain;
}

TokenKind DecompilerView::classifyCWord(const QString& id) {
    if (cTypes().contains(id))    return TokenKind::Type;
    if (cKeywords().contains(id)) return TokenKind::Keyword;
    TokenKind decKind = classifyDecompilerWord(id);
    if (decKind != TokenKind::Plain) return decKind;
    return TokenKind::Plain;
}

// ── Simple C tokenizer ───────────────────────────────────────────────────────

std::vector<Token> DecompilerView::tokenizeCLine(const QString& line, int& braceDepth, int& parenDepth) {
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
            tryResolveStringToken(QVector<Token>(result.begin(), result.end()), t); // (char *)0xHEX → "string literal"
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

        // ── braces {} with depth tracking ──
        if (c == '{' || c == '}') {
            Token t;
            t.text = line.mid(i, 1);
            if (c == '{') {
                t.kind = (braceDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
                ++braceDepth;
            } else {
                --braceDepth;
                t.kind = (braceDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
            }
            result.push_back(t);
            ++i;
            continue;
        }

        // ── parens () with depth tracking ──
        if (c == '(' || c == ')') {
            Token t;
            t.text = line.mid(i, 1);
            if (c == '(') {
                t.kind = (parenDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
                ++parenDepth;
            } else {
                --parenDepth;
                t.kind = (parenDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
            }
            result.push_back(t);
            ++i;
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
                Token t; t.text = two; t.kind = TokenKind::Operator;
                result.push_back(t);
                i += 2;
                continue;
            }
        }

        // ── single-char punctuation / operator ──
        {
            Token t; t.text = line.mid(i, 1);
            QChar ch = line[i];
            if (ch == ';')
                t.kind = TokenKind::Semicolon;
            else if (ch == '.' || ch == ',' || ch == '[' || ch == ']' ||
                     ch == '=' || ch == '+' || ch == '-' || ch == '*' ||
                     ch == '/' || ch == '|' || ch == '&' || ch == '^' ||
                     ch == '<' || ch == '>' || ch == '!' || ch == '~' ||
                     ch == '?')
                t.kind = TokenKind::Operator;
            else
                t.kind = TokenKind::Punctuation;
            result.push_back(t);
            ++i;
        }
    }

    return result;
}

// ── Public API ───────────────────────────────────────────────────────────────

static TokenKind kindForMarkupElement(const QString& name, int color, const QString& content) {
    if (name == QStringLiteral("variable")) return TokenKind::Variable;
    if (name == QStringLiteral("funcname")) return TokenKind::Function;
    if (name == QStringLiteral("type")) return TokenKind::Type;
    if (name == QStringLiteral("comment")) return TokenKind::Comment;
    if (name == QStringLiteral("label")) return TokenKind::Label;
    if (name == QStringLiteral("field")) return TokenKind::Variable;
    if (name == QStringLiteral("value")) return TokenKind::Immediate;
    if (name == QStringLiteral("op")) {
        if (color == 0) return TokenKind::Keyword;
        QString t = content.trimmed();
        if (t == QStringLiteral(";")) return TokenKind::Semicolon;
        if (t.size() == 1) {
            QChar ch = t[0];
            if (ch == '=' || ch == '+' || ch == '-' || ch == '*' ||
                ch == '/' || ch == '|' || ch == '&' || ch == '^' ||
                ch == '<' || ch == '>')
                return TokenKind::Operator;
        }
        return TokenKind::Operator;
    }
    if (name == QStringLiteral("syntax")) {
        if (content.trimmed().isEmpty()) return TokenKind::Plain;
        QString t = content.trimmed();
        if (t == QStringLiteral(";")) return TokenKind::Semicolon;
        if (cKeywords().contains(t)) return TokenKind::Keyword;
        if (cTypes().contains(t))    return TokenKind::Type;
        if (t.startsWith(QStringLiteral("__"))) return TokenKind::Operator;
        if (t.size() == 1) {
            QChar ch = t[0];
            if (ch == '.' || ch == ',' || ch == '[' || ch == ']' ||
                ch == '=' || ch == '+' || ch == '-' || ch == '*' ||
                ch == '/' || ch == '|' || ch == '&' || ch == '^' ||
                ch == '<' || ch == '>' || ch == '!' || ch == '~' ||
                ch == '?')
                return TokenKind::Operator;
        }
        return TokenKind::Punctuation;
    }
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
    int braceDepth = 0;
    int parenDepth = 0;

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

        bool colorOk = false;
        int color = static_cast<int>(attrULL(attrs, QStringLiteral("color"), &colorOk));

        const QString content = xml.readElementText();
        if (content.isEmpty())
            continue;

        if (content.trimmed().isEmpty()) {
            int spaces = content.size();
            if (!line.tokens.isEmpty())
                line.tokens.back().spaceAfter += spaces;
            else {
                Token pad;
                pad.spaceAfter = spaces;
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
            t.kind = kindForMarkupElement(name, colorOk ? color : -1, parts[i]);
            // Refine tokens that look like decompiler identifiers
            if (t.kind == TokenKind::Plain) {
                TokenKind refined = classifyCWord(parts[i]);
                if (refined != TokenKind::Plain)
                    t.kind = refined;
            }
            // Apply depth-based coloring for braces and parens in syntax tokens
            if (t.kind == TokenKind::Punctuation) {
                QString trimmed = parts[i].trimmed();
                if (trimmed == QStringLiteral("{") || trimmed == QStringLiteral("}")) {
                    if (trimmed == QStringLiteral("{")) {
                        t.kind = (braceDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
                        ++braceDepth;
                    } else {
                        --braceDepth;
                        t.kind = (braceDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
                    }
                } else if (trimmed == QStringLiteral("(") || trimmed == QStringLiteral(")")) {
                    if (trimmed == QStringLiteral("(")) {
                        t.kind = (parenDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
                        ++parenDepth;
                    } else {
                        --parenDepth;
                        t.kind = (parenDepth == 0) ? TokenKind::BracesOuter : TokenKind::BracesInner;
                    }
                }
            }
            t.addr = tokenAddr != 0 ? tokenAddr : (statementAddr != 0 ? statementAddr : funcAddr);
            if (line.addr == 0)
                line.addr = t.addr;
            tryResolveStringToken(line.tokens, t); // (char *)0xHEX → "string literal"
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

    int braceDepth = 0;
    int parenDepth = 0;

    for (const QString& raw : rawLines) {
        Line l;
        l.addr = funcAddr;   // all lines map to the function entry

        if (raw.trimmed().isEmpty()) {
            // Preserve blank lines for readability
            doc->addLine(std::move(l));
            continue;
        }

        auto tokens = tokenizeCLine(raw, braceDepth, parenDepth);
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
