#pragma once

#include <string>

namespace ghidra {

class FunctionTag {
public:
    virtual ~FunctionTag() = default;

    virtual long getId() const = 0;
    virtual std::string getName() const = 0;
    virtual std::string getComment() const = 0;

    virtual void setName(const std::string& name) = 0;
    virtual void setComment(const std::string& comment) = 0;
    virtual void deleteTag() = 0;
};

} // namespace ghidra
