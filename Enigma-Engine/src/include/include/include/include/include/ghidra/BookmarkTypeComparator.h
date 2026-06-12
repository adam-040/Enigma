#pragma once

#include <ghidra/BookmarkType.h>
#include <string>

namespace ghidra {

struct BookmarkTypeComparator {
    bool operator()(BookmarkType bt1, BookmarkType bt2) const {
        return bookmarkTypeToString(bt1) < bookmarkTypeToString(bt2);
    }
};

} // namespace ghidra
