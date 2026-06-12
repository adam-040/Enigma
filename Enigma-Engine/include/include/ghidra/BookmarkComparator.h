#pragma once

#include <ghidra/Bookmark.h>
#include <string>

namespace ghidra {

struct BookmarkComparator {
    bool operator()(const Bookmark* bm1, const Bookmark* bm2) const {
        int typeCompare = bm1->getTypeString().compare(bm2->getTypeString());
        if (typeCompare == 0) {
            return bm1->getCategory() < bm2->getCategory();
        }
        return typeCompare < 0;
    }

    bool equals(const Bookmark* bm1, const Bookmark* bm2) const {
        return bm1->getTypeString() == bm2->getTypeString() &&
               bm1->getCategory() == bm2->getCategory();
    }
};

} // namespace ghidra
