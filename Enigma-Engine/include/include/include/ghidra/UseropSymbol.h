#pragma once

#include <ghidra/Decoder.h>
#include <string>

namespace ghidra {

class SleighLanguage;

class UseropSymbol {
private:
    std::string name_;
    int id_ = 0;
    int scopeId_ = 0;
    int index_ = 0;

public:
    UseropSymbol() = default;
    UseropSymbol(const std::string& name, int id, int scopeId, int index)
        : name_(name), id_(id), scopeId_(scopeId), index_(index) {}

    const std::string& getName() const { return name_; }
    int getId() const { return id_; }
    int getScopeId() const { return scopeId_; }
    int getIndex() const { return index_; }

    void decodeHeader(Decoder* decoder);
    void decode(Decoder* decoder, SleighLanguage* sleigh);
};

} // namespace ghidra
