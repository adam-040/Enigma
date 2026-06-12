#pragma once

#include <string>

namespace ghidra {

class Symbol;

class LabelString {
public:
    enum class LabelType {
        CODE_LABEL,
        VARIABLE,
        EXTERNAL
    };

    LabelString(const std::string& label, LabelType type)
        : label_(label), type_(type), symbol_(nullptr) {}

    LabelString(const std::string& label, Symbol* symbol, LabelType type)
        : label_(label), symbol_(symbol), type_(type) {}

    Symbol* getSymbol() const { return symbol_; }
    const std::string& getLabel() const { return label_; }
    LabelType getLabelType() const { return type_; }

    std::string toString() const { return label_; }

private:
    std::string label_;
    Symbol* symbol_;
    LabelType type_;
};

} // namespace ghidra
