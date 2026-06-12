#include <ghidra/Comment.h>
#include <algorithm>

namespace ghidra {

Comment::Comment() : type(EOL_COMMENT), id(-1) {
}

Comment::Comment(const Address& addr, const std::string& txt, Type t, const std::string& auth, int4 commentId)
    : address(addr), text(txt), type(t), author(auth), id(commentId) {
}

std::string Comment::typeToString(Type t) {
    switch (t) {
        case EOL_COMMENT: return "EOL";
        case PRE_COMMENT: return "PRE";
        case POST_COMMENT: return "POST";
        case MID_COMMENT: return "MID";
        case WARNING_COMMENT: return "WARNING";
        case EXCEPTION_COMMENT: return "EXCEPTION";
        case BOOKMARK_COMMENT: return "BOOKMARK";
        case REPEATABLE_COMMENT: return "REPEATABLE";
        case PLATE_COMMENT: return "PLATE";
        case HEADER_COMMENT: return "HEADER";
        case FOOTER_COMMENT: return "FOOTER";
        default: return "UNKNOWN";
    }
}

Comment::Type Comment::stringToType(const std::string& s) {
    if (s == "EOL") return EOL_COMMENT;
    if (s == "PRE") return PRE_COMMENT;
    if (s == "POST") return POST_COMMENT;
    if (s == "MID") return MID_COMMENT;
    if (s == "WARNING") return WARNING_COMMENT;
    if (s == "EXCEPTION") return EXCEPTION_COMMENT;
    if (s == "BOOKMARK") return BOOKMARK_COMMENT;
    if (s == "REPEATABLE") return REPEATABLE_COMMENT;
    if (s == "PLATE") return PLATE_COMMENT;
    if (s == "HEADER") return HEADER_COMMENT;
    if (s == "FOOTER") return FOOTER_COMMENT;
    return TYPE_LAST;
}

CommentDatabase::CommentDatabase() : nextId(0) {
}

int4 CommentDatabase::addComment(const Address& addr, const std::string& text, Comment::Type type, const std::string& author) {
    int4 id = nextId++;
    Comment comment(addr, text, type, author, id);
    comments[id] = comment;
    addressIndex.insert(std::make_pair(addr, id));
    typeIndex.insert(std::make_pair(type, id));
    return id;
}

bool CommentDatabase::removeComment(int4 id) {
    auto it = comments.find(id);
    if (it == comments.end()) return false;

    const Comment& comment = it->second;
    auto ait = addressIndex.find(comment.getAddress());
    while (ait != addressIndex.end() && ait->first == comment.getAddress()) {
        if (ait->second == id) {
            ait = addressIndex.erase(ait);
            break;
        } else {
            ++ait;
        }
    }

    auto tit = typeIndex.find(comment.getType());
    while (tit != typeIndex.end() && tit->first == comment.getType()) {
        if (tit->second == id) {
            tit = typeIndex.erase(tit);
            break;
        } else {
            ++tit;
        }
    }

    comments.erase(it);
    return true;
}

bool CommentDatabase::removeCommentsAt(const Address& addr) {
    auto range = addressIndex.equal_range(addr);
    std::vector<int4> toRemove;
    for (auto it = range.first; it != range.second; ++it) {
        toRemove.push_back(it->second);
    }

    for (int4 id : toRemove) {
        comments.erase(id);
    }

    addressIndex.erase(addr);
    return !toRemove.empty();
}

bool CommentDatabase::removeCommentsByType(Comment::Type type) {
    auto range = typeIndex.equal_range(type);
    std::vector<int4> toRemove;
    for (auto it = range.first; it != range.second; ++it) {
        toRemove.push_back(it->second);
    }

    for (int4 id : toRemove) {
        comments.erase(id);
    }

    typeIndex.erase(type);
    return !toRemove.empty();
}

Comment* CommentDatabase::getComment(int4 id) {
    auto it = comments.find(id);
    return (it != comments.end()) ? &it->second : nullptr;
}

const Comment* CommentDatabase::getComment(int4 id) const {
    auto it = comments.find(id);
    return (it != comments.end()) ? &it->second : nullptr;
}

std::vector<Comment*> CommentDatabase::getCommentsAt(const Address& addr) {
    std::vector<Comment*> result;
    auto range = addressIndex.equal_range(addr);
    for (auto it = range.first; it != range.second; ++it) {
        auto cit = comments.find(it->second);
        if (cit != comments.end()) {
            result.push_back(&cit->second);
        }
    }
    return result;
}

std::vector<const Comment*> CommentDatabase::getCommentsAt(const Address& addr) const {
    std::vector<const Comment*> result;
    auto range = addressIndex.equal_range(addr);
    for (auto it = range.first; it != range.second; ++it) {
        auto cit = comments.find(it->second);
        if (cit != comments.end()) {
            result.push_back(&cit->second);
        }
    }
    return result;
}

std::vector<Comment*> CommentDatabase::getCommentsByType(Comment::Type type) {
    std::vector<Comment*> result;
    auto range = typeIndex.equal_range(type);
    for (auto it = range.first; it != range.second; ++it) {
        auto cit = comments.find(it->second);
        if (cit != comments.end()) {
            result.push_back(&cit->second);
        }
    }
    return result;
}

std::vector<const Comment*> CommentDatabase::getCommentsByType(Comment::Type type) const {
    std::vector<const Comment*> result;
    auto range = typeIndex.equal_range(type);
    for (auto it = range.first; it != range.second; ++it) {
        auto cit = comments.find(it->second);
        if (cit != comments.end()) {
            result.push_back(&cit->second);
        }
    }
    return result;
}

std::vector<Comment*> CommentDatabase::getAllComments() {
    std::vector<Comment*> result;
    for (auto& pair : comments) {
        result.push_back(&pair.second);
    }
    return result;
}

std::vector<const Comment*> CommentDatabase::getAllComments() const {
    std::vector<const Comment*> result;
    for (const auto& pair : comments) {
        result.push_back(&pair.second);
    }
    return result;
}

void CommentDatabase::clear() {
    comments.clear();
    addressIndex.clear();
    typeIndex.clear();
    nextId = 0;
}

} // namespace ghidra
