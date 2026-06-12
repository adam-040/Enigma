#pragma once

#include <ghidra/Address.h>
#include <ghidra/BookmarkType.h>
#include <string>

namespace ghidra {

class Bookmark {
public:
    virtual ~Bookmark() = default;

    virtual long getId() const = 0;
    virtual Address getAddress() const = 0;
    virtual BookmarkType getType() const = 0;
    virtual std::string getTypeString() const = 0;
    virtual std::string getCategory() const = 0;
    virtual std::string getComment() const = 0;
    virtual void set(const std::string& category, const std::string& comment) = 0;

    bool operator<(const Bookmark& other) const;
    bool operator==(const Bookmark& other) const;
};

} // namespace ghidra
