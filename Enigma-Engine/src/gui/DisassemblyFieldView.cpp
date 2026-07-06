#include "DisassemblyFieldView.h"
#include <ghidra/ProgramDB.h>
#include <ghidra/DecompInterface.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>

DisassemblyFieldView::DisassemblyFieldView(QWidget* parent)
    : FieldView(parent)
{
}

void DisassemblyFieldView::setProgram(ghidra::ProgramDB* program) {
    program_ = program;
    indexBuilt_ = false;
}

void DisassemblyFieldView::setDecompInterface(ghidra::DecompInterface* decomp) {
    decomp_ = decomp;
    indexBuilt_ = false;
}

void DisassemblyFieldView::setShowBytes(bool show) {
    showBytes_ = show;
    if (parsed_.empty() && !lastText_.isEmpty()) {
        showDisassembly(lastText_);
    } else if (!parsed_.empty()) {
        uint64_t currentAddr = addressAtCurrentLine();
        buildDocumentFromParsed();
        if (currentAddr != 0)
            seek(currentAddr);
    }
}

bool DisassemblyFieldView::showBytes() const {
    return showBytes_;
}

void DisassemblyFieldView::buildFullIndex() {
    if (!program_ || !decomp_ || !decomp_->isOpen())
        return;

    auto* mem = program_->getMemory();
    auto* af = program_->getAddressFactory();
    if (!mem || !af) return;

    auto allBlocks = mem->getBlocks();
    if (allBlocks.empty()) return;

    QString allText;
    for (auto* block : allBlocks) {
        if (!block) continue;
        int flags = block->getFlags();
        if (!(flags & ghidra::MemoryBlock::FLAG_EXECUTE)) continue;

        uint64_t start = block->getStart().getUnsignedOffset();
        ghidra::Address gAddr = af->oldGetAddressFromLong(start);
        std::string text = decomp_->disassembleAt(gAddr, 100000000);
        allText += QString::fromStdString(text);
    }

    if (allText.isEmpty())
        return;

    indexBuilt_ = true;
    lastText_ = allText;
    showDisassembly(allText);
}

void DisassemblyFieldView::seekToAddress(uint64_t addr) {
    if (!indexBuilt_ || !document())
        return;

    seek(addr);
}

static bool isCommentLine(const QString& trimmed) {
    return trimmed.startsWith(QLatin1Char(';'))
        || trimmed.startsWith(QStringLiteral("//"));
}

static std::vector<uint8_t> fetchBytesLocal(ghidra::ProgramDB* program, uint64_t addr, int len) {
    if (!program || len <= 0) return {};
    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    if (!mem || !af) return {};
    ghidra::Address a = af->oldGetAddressFromLong(addr);
    std::vector<uint8_t> buf(len);
    int got = mem->getBytes(a, buf.data(), len);
    if (got > 0) {
        buf.resize(got);
        return buf;
    }
    return {};
}

void DisassemblyFieldView::showDisassembly(const QString& text) {
    lastText_ = text;
    parsed_.clear();

    QString expanded = text;
    expanded.replace(QLatin1Char('\t'), QString(8, QLatin1Char(' ')));
    QStringList rawLines = expanded.split(QLatin1Char('\n'));

    parsed_.reserve(rawLines.size());

    static QRegularExpression instRe(
        QStringLiteral("^0x([0-9a-fA-F]+):\\s+([A-Za-z][A-Za-z0-9]*)\\s*(.*)$"));

    for (const QString& rawLine : rawLines) {
        if (rawLine.trimmed().isEmpty()) {
            parsed_.push_back(ParsedLine{});
            continue;
        }
        QString trimmed = rawLine.trimmed();
        if (isCommentLine(trimmed)) {
            ParsedLine rl;
            rl.body = trimmed;
            parsed_.push_back(rl);
            continue;
        }
        auto m = instRe.match(trimmed);
        if (m.hasMatch()) {
            ParsedLine rl;
            bool ok = false;
            rl.addr = m.captured(1).toULongLong(&ok, 16);
            rl.mne = m.captured(2);
            rl.body = m.captured(3);
            parsed_.push_back(rl);
        } else {
            ParsedLine rl;
            rl.body = trimmed;
            parsed_.push_back(rl);
        }
    }

    buildDocumentFromParsed();
}

void DisassemblyFieldView::buildDocumentFromParsed() {
    auto doc = std::make_unique<Document>();

    for (size_t i = 0; i < parsed_.size(); ++i) {
        const ParsedLine& rl = parsed_[i];
        if (rl.body.isEmpty() && rl.mne.isEmpty()) {
            doc->addLine(Line{});
            continue;
        }

        Line l;
        l.addr = rl.addr;

        if (!rl.mne.isEmpty()) {
            Token addrTok;
            addrTok.text = QStringLiteral("0x%1  ").arg(rl.addr, 8, 16, QLatin1Char('0'));
            addrTok.kind = TokenKind::Address;
            addrTok.addr = rl.addr;
            l.tokens.push_back(addrTok);

            int len = 0;
            if (i + 1 < parsed_.size() && parsed_[i + 1].addr > rl.addr)
                len = static_cast<int>(parsed_[i + 1].addr - rl.addr);
            else if (decomp_)
                len = decomp_->instructionLengthAt(rl.addr);

            if (showBytes_ && len > 0) {
                l.bytes = fetchBytesLocal(program_, rl.addr, len);
                Token bytesTok;
                bytesTok.text = formatBytes(l.bytes);
                bytesTok.kind = TokenKind::Bytes;
                bytesTok.addr = rl.addr;
                int gap = 30 - static_cast<int>(bytesTok.text.size());
                bytesTok.spaceAfter = (gap >= 2) ? gap : 2;
                l.tokens.push_back(bytesTok);
            }

            Token mneTok;
            mneTok.text = rl.mne.leftJustified(8, QLatin1Char(' '));
            mneTok.kind = isBranchMnemonic(rl.mne) ? TokenKind::Branch : TokenKind::Mnemonic;
            mneTok.addr = rl.addr;
            l.tokens.push_back(mneTok);

            auto opTokens = tokenizeOperands(rl.body, rl.addr);
            for (auto& t : opTokens)
                l.tokens.push_back(t);

        } else {
            Token t;
            t.text = rl.body;
            t.kind = isCommentLine(rl.body) ? TokenKind::Comment : TokenKind::Plain;
            l.tokens.push_back(t);
        }

        doc->addLine(l);
    }

    doc->finalize();
    setDocument(std::move(doc));
}

QString DisassemblyFieldView::formatBytes(const std::vector<uint8_t>& bytes) {
    QString out;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i) out += QLatin1Char(' ');
        out += QStringLiteral("%1").arg(bytes[i], 2, 16, QLatin1Char('0'));
    }
    return out;
}

bool DisassemblyFieldView::isBranchMnemonic(const QString& mne) {
    static const QStringList branch = {
        QStringLiteral("CALL"), QStringLiteral("JMP"), QStringLiteral("JMPF"),
        QStringLiteral("JE"), QStringLiteral("JNE"), QStringLiteral("JZ"), QStringLiteral("JNZ"),
        QStringLiteral("JA"), QStringLiteral("JAE"), QStringLiteral("JB"), QStringLiteral("JBE"),
        QStringLiteral("JG"), QStringLiteral("JGE"), QStringLiteral("JL"), QStringLiteral("JLE"),
        QStringLiteral("JO"), QStringLiteral("JNO"), QStringLiteral("JS"), QStringLiteral("JNS"),
        QStringLiteral("JP"), QStringLiteral("JNP"), QStringLiteral("JC"), QStringLiteral("JNC"),
        QStringLiteral("RET"), QStringLiteral("RETN"), QStringLiteral("RETF"),
        QStringLiteral("IRET"), QStringLiteral("IRETD"), QStringLiteral("IRETQ"),
        QStringLiteral("SYSCALL"), QStringLiteral("SYSRET"), QStringLiteral("SYSENTER"),
        QStringLiteral("INT"), QStringLiteral("INT3"), QStringLiteral("INTO"),
        QStringLiteral("LOOP"), QStringLiteral("LOOPE"), QStringLiteral("LOOPNE"),
        QStringLiteral("LOOPZ"), QStringLiteral("LOOPNZ")
    };
    return branch.contains(mne.toUpper());
}

TokenKind DisassemblyFieldView::classifyIdentifier(const QString& id) const {
    static const QStringList registers = {
        QStringLiteral("eax"), QStringLiteral("ebx"), QStringLiteral("ecx"),
        QStringLiteral("edx"), QStringLiteral("esi"), QStringLiteral("edi"),
        QStringLiteral("ebp"), QStringLiteral("esp"), QStringLiteral("eip"),
        QStringLiteral("rax"), QStringLiteral("rbx"), QStringLiteral("rcx"),
        QStringLiteral("rdx"), QStringLiteral("rsi"), QStringLiteral("rdi"),
        QStringLiteral("rbp"), QStringLiteral("rsp"), QStringLiteral("rip"),
        QStringLiteral("r8"),  QStringLiteral("r9"),  QStringLiteral("r10"),
        QStringLiteral("r11"), QStringLiteral("r12"), QStringLiteral("r13"),
        QStringLiteral("r14"), QStringLiteral("r15"),
        QStringLiteral("r8d"), QStringLiteral("r9d"), QStringLiteral("r10d"),
        QStringLiteral("r11d"),QStringLiteral("r12d"),QStringLiteral("r13d"),
        QStringLiteral("r14d"),QStringLiteral("r15d"),
        QStringLiteral("r8w"), QStringLiteral("r9w"), QStringLiteral("r10w"),
        QStringLiteral("r11w"),QStringLiteral("r12w"),QStringLiteral("r13w"),
        QStringLiteral("r14w"),QStringLiteral("r15w"),
        QStringLiteral("r8b"), QStringLiteral("r9b"), QStringLiteral("r10b"),
        QStringLiteral("r11b"),QStringLiteral("r12b"),QStringLiteral("r13b"),
        QStringLiteral("r14b"),QStringLiteral("r15b"),
        QStringLiteral("ax"),  QStringLiteral("bx"),  QStringLiteral("cx"),
        QStringLiteral("dx"),  QStringLiteral("si"),  QStringLiteral("di"),
        QStringLiteral("bp"),  QStringLiteral("sp"),
        QStringLiteral("ah"),  QStringLiteral("bh"),  QStringLiteral("ch"),
        QStringLiteral("dh"),  QStringLiteral("al"),  QStringLiteral("bl"),
        QStringLiteral("cl"),  QStringLiteral("dl"),
        QStringLiteral("sil"), QStringLiteral("dil"), QStringLiteral("bpl"),
        QStringLiteral("spl"),
        QStringLiteral("xmm0"), QStringLiteral("xmm1"), QStringLiteral("xmm2"),
        QStringLiteral("xmm3"), QStringLiteral("xmm4"), QStringLiteral("xmm5"),
        QStringLiteral("xmm6"), QStringLiteral("xmm7"),
        QStringLiteral("ymm0"), QStringLiteral("ymm1"), QStringLiteral("ymm2"),
        QStringLiteral("ymm3"), QStringLiteral("ymm4"), QStringLiteral("ymm5"),
        QStringLiteral("ymm6"), QStringLiteral("ymm7"),
        QStringLiteral("cs"),  QStringLiteral("ds"),  QStringLiteral("es"),
        QStringLiteral("fs"),  QStringLiteral("gs"),  QStringLiteral("ss"),
        QStringLiteral("st0"), QStringLiteral("st1"), QStringLiteral("st2"),
        QStringLiteral("st3"), QStringLiteral("st4"), QStringLiteral("st5"),
        QStringLiteral("st6"), QStringLiteral("st7"),
    };
    QString lower = id.toLower();
    if (registers.contains(lower))
        return TokenKind::Register;
    bool allDigits = true;
    for (const QChar& c : id) {
        if (!c.isDigit()) { allDigits = false; break; }
    }
    if (allDigits) return TokenKind::Number;
    return TokenKind::Plain;
}

std::vector<Token> DisassemblyFieldView::tokenizeOperands(const QString& ops, uint64_t lineAddr) {
    std::vector<Token> result;
    int n = ops.size();
    int i = 0;
    int bracketDepth = 0;

    auto consumeSpaces = [&](int pos) {
        while (pos < n && ops[pos].isSpace()) ++pos;
        return pos;
    };

    auto addToken = [&](const QString& text, TokenKind kind) {
        if (text.isEmpty()) return;
        Token t;
        t.text = text;
        t.kind = kind;
        t.addr = lineAddr;
        result.push_back(t);
    };

    while (i < n) {
        QChar c = ops[i];
        if (c.isSpace()) {
            ++i;
            continue;
        }

        if (c == QLatin1Char('0') && i + 1 < n && ops[i + 1] == QLatin1Char('x')) {
            int j = i + 2;
            while (j < n && (ops[j].isDigit() ||
                             (ops[j] >= QLatin1Char('a') && ops[j] <= QLatin1Char('f')) ||
                             (ops[j] >= QLatin1Char('A') && ops[j] <= QLatin1Char('F')))) ++j;
            QString txt = ops.mid(i, j - i);
            Token t;
            t.text = txt;
            t.kind = bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Immediate;
            t.addr = lineAddr;
            bool ok = false;
            uint64_t val = txt.mid(2).toULongLong(&ok, 16);
            if (ok && val > 0x1000) t.refTarget = val;
            result.push_back(t);
            i = consumeSpaces(j);
            result.back().spaceAfter = i - j;
            continue;
        }

        if (c.isLetter() || c == QLatin1Char('_')) {
            int j = i;
            while (j < n && (ops[j].isLetterOrNumber() || ops[j] == QLatin1Char('_'))) ++j;
            QString id = ops.mid(i, j - i);
            TokenKind k = classifyIdentifier(id);
            if (bracketDepth > 0 && k != TokenKind::Register) k = TokenKind::MemRef;
            addToken(id, k);
            i = consumeSpaces(j);
            result.back().spaceAfter = i - j;
            continue;
        }

        if (c == QLatin1Char('[')) {
            addToken(QStringLiteral("["), TokenKind::MemRef);
            ++bracketDepth;
            ++i;
            continue;
        }
        if (c == QLatin1Char(']')) {
            addToken(QStringLiteral("]"), TokenKind::MemRef);
            if (bracketDepth > 0) --bracketDepth;
            ++i;
            continue;
        }

        if (c == QLatin1Char('+') || c == QLatin1Char('-') || c == QLatin1Char('*') ||
            c == QLatin1Char(',') || c == QLatin1Char(':') ||
            c == QLatin1Char('(') || c == QLatin1Char(')')) {
            addToken(ops.mid(i, 1), bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Punctuation);
            ++i;
            continue;
        }

        addToken(ops.mid(i, 1), bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Plain);
        ++i;
    }
    return result;
}
