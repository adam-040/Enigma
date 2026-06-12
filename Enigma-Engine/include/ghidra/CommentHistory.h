#pragma once

#include <ghidra/Address.h>
#include <ghidra/CommentType.h>
#include <string>
#include <chrono>

namespace ghidra {

class CommentHistory {
private:
    Address addr_;
    CommentType commentType_;
    std::string userName_;
    std::string comments_;
    std::chrono::system_clock::time_point modificationDate_;

public:
    CommentHistory(const Address& addr, CommentType commentType,
                   const std::string& userName, const std::string& comments,
                   const std::chrono::system_clock::time_point& modificationDate)
        : addr_(addr), commentType_(commentType), userName_(userName),
          comments_(comments), modificationDate_(modificationDate) {}

    const Address& getAddress() const { return addr_; }
    CommentType getCommentType() const { return commentType_; }
    const std::string& getUserName() const { return userName_; }
    const std::string& getComments() const { return comments_; }
    const std::chrono::system_clock::time_point& getModificationDate() const { return modificationDate_; }

    std::string toString() const;
};

} // namespace ghidra
