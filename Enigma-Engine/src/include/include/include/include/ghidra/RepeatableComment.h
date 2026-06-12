#pragma once

#include <string>

namespace ghidra {

class RepeatableComment {
public:
    virtual ~RepeatableComment() = default;

    virtual std::string getComment() const = 0;
    virtual void setComment(const std::string& comment) = 0;
};

} // namespace ghidra
