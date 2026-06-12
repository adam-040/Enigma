#pragma once

#include <ghidra/Address.h>
#include <vector>
#include <string>
#include <memory>

namespace ghidra {

class ConstructState;
class ParserWalker;
class SleighLanguage;

class Constructor {
public:
    Constructor() = default;
    Constructor(SleighLanguage* lang, int index)
        : language_(lang), index_(index) {}

    int getIndex() const { return index_; }
    const std::string& getName() const { return name_; }
    void setName(const std::string& name) { name_ = name; }
    int getLength() const { return length_; }
    void setLength(int len) { length_ = len; }

    SleighLanguage* getLanguage() const { return language_; }

private:
    SleighLanguage* language_ = nullptr;
    int index_ = 0;
    std::string name_;
    int length_ = 0;
};

} // namespace ghidra
