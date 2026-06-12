#pragma once

#include <string>

namespace ghidra {

class Funcdata;

class HighFunction {
private:
    Funcdata* fd;
    std::string name;

public:
    HighFunction(Funcdata* f);
    ~HighFunction() = default;

    Funcdata* getFuncdata() const { return fd; }
    const std::string& getName() const { return name; }
    void setName(const std::string& n) { name = n; }
};

} // namespace ghidra
