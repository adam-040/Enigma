#pragma once

#include <ghidra/CommentType.h>
#include <string>
#include <vector>
#include <stdexcept>

namespace ghidra {

class CodeUnitComments {
public:
    static constexpr int NUM_COMMENT_TYPES = 5;

    explicit CodeUnitComments(const std::vector<std::string>& comments) : comments_(comments) {
        if (comments_.size() != NUM_COMMENT_TYPES) {
            throw std::invalid_argument("comment array size does not match enum size");
        }
    }

    std::string getComment(CommentType type) const {
        int idx = static_cast<int>(type);
        if (idx >= 0 && idx < static_cast<int>(comments_.size())) {
            return comments_[idx];
        }
        return "";
    }

    void setComment(CommentType type, const std::string& comment) {
        int idx = static_cast<int>(type);
        if (idx >= 0 && idx < static_cast<int>(comments_.size())) {
            comments_[idx] = comment;
        }
    }

private:
    std::vector<std::string> comments_;
};

} // namespace ghidra
