#pragma once

#include <ghidra/Address.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace ghidra {

typedef int32_t int4;

class Comment {
public:
    enum Type {
        EOL_COMMENT = 0,
        PRE_COMMENT = 1,
        POST_COMMENT = 2,
        MID_COMMENT = 3,
        WARNING_COMMENT = 4,
        EXCEPTION_COMMENT = 5,
        BOOKMARK_COMMENT = 6,
        REPEATABLE_COMMENT = 7,
        PLATE_COMMENT = 8,
        HEADER_COMMENT = 9,
        FOOTER_COMMENT = 10,
        TYPE_LAST = 11
    };

private:
    Address address;
    std::string text;
    Type type;
    std::string author;
    int4 id;

public:
    Comment();
    Comment(const Address& addr, const std::string& txt, Type t, const std::string& auth, int4 commentId);
    ~Comment() = default;

    const Address& getAddress() const { return address; }
    const std::string& getText() const { return text; }
    Type getType() const { return type; }
    const std::string& getAuthor() const { return author; }
    int4 getId() const { return id; }

    void setText(const std::string& txt) { text = txt; }

    static std::string typeToString(Type t);
    static Type stringToType(const std::string& s);

    bool operator==(const Comment& other) const { return id == other.id; }
    bool operator!=(const Comment& other) const { return id != other.id; }
};

class CommentDatabase {
private:
    std::map<int4, Comment> comments;
    std::multimap<Address, int4> addressIndex;
    std::multimap<Comment::Type, int4> typeIndex;
    int4 nextId;

public:
    CommentDatabase();
    ~CommentDatabase() = default;

    int4 addComment(const Address& addr, const std::string& text, Comment::Type type, const std::string& author = "user");
    bool removeComment(int4 id);
    bool removeCommentsAt(const Address& addr);
    bool removeCommentsByType(Comment::Type type);

    Comment* getComment(int4 id);
    const Comment* getComment(int4 id) const;

    std::vector<Comment*> getCommentsAt(const Address& addr);
    std::vector<const Comment*> getCommentsAt(const Address& addr) const;
    std::vector<Comment*> getCommentsByType(Comment::Type type);
    std::vector<const Comment*> getCommentsByType(Comment::Type type) const;
    std::vector<Comment*> getAllComments();
    std::vector<const Comment*> getAllComments() const;

    int4 getNumComments() const { return static_cast<int4>(comments.size()); }
    int4 getNextId() const { return nextId; }

    void clear();
};

} // namespace ghidra
