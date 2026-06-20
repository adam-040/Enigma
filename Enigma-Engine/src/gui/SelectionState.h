#pragma once

#include <cstdint>
#include <QString>

enum class TokenKind {
    Plain, Address, Bytes, Mnemonic, Branch, Register, Immediate,
    Number, MemRef, Punctuation, Label, Function, Variable,
    Type, Keyword, String, Comment
};

struct SelectionState {
    uint64_t address = 0;      // instruction start address
    uint64_t endAddress = 0;   // instruction end address (exclusive); 0 if unknown
    QString tokenText;         // selected token text, empty if none
    TokenKind tokenKind = TokenKind::Plain;
    QObject* originView = nullptr; // view that originated this selection (prevents feedback)
    bool valid = false;

    bool operator==(const SelectionState& other) const {
        return valid == other.valid &&
               address == other.address &&
               endAddress == other.endAddress &&
               tokenText == other.tokenText &&
               tokenKind == other.tokenKind &&
               originView == other.originView;
    }
    bool operator!=(const SelectionState& other) const { return !(*this == other); }
};
