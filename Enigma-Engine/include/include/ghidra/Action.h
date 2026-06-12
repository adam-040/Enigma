#pragma once

#include <ghidra/Address.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

typedef int32_t int4;
typedef uint32_t uint4;

class Funcdata;

class Action {
public:
    enum Status {
        STATUS_NONE = 0,
        STATUS_APPLIED = 1,
        STATUS_SKIPPED = 2,
        STATUS_BREAK = 4,
        STATUS_REPEAT = 8
    };

    enum Category {
        CATEGORY_CONSTANT = 0x0001,
        CATEGORY_COPY = 0x0002,
        CATEGORY_DEADCODE = 0x0004,
        CATEGORY_MERGE = 0x0008,
        CATEGORY_TYPEPROP = 0x0010,
        CATEGORY_RULE = 0x0020,
        CATEGORY_TRANSFORM = 0x0040,
        CATEGORY_ALL = 0xFFFF
    };

protected:
    std::string name;
    std::string comment;
    uint4 category;
    bool enabled;
    int4 applyCount;

public:
    Action(const std::string& nm, uint4 cat, const std::string& cmt);
    virtual ~Action() = default;

    virtual uint4 apply(Funcdata& fd) = 0;

    const std::string& getName() const { return name; }
    const std::string& getComment() const { return comment; }
    uint4 getCategory() const { return category; }
    bool isEnabled() const { return enabled; }
    int4 getApplyCount() const { return applyCount; }

    void setEnabled(bool val) { enabled = val; }
    void resetCount() { applyCount = 0; }

    bool isApplied(uint4 status) const { return (status & STATUS_APPLIED) != 0; }
    bool isSkipped(uint4 status) const { return (status & STATUS_SKIPPED) != 0; }
    bool shouldBreak(uint4 status) const { return (status & STATUS_BREAK) != 0; }
    bool shouldRepeat(uint4 status) const { return (status & STATUS_REPEAT) != 0; }
};

class ActionList {
private:
    std::vector<Action*> actions;
    std::string name;
    uint4 filterCategory;
    int4 maxIterations;

public:
    ActionList(const std::string& nm, uint4 filter = Action::CATEGORY_ALL, int4 maxIter = 100);
    ~ActionList();

    void addAction(Action* action);
    void removeAction(Action* action);
    void clear();

    uint4 execute(Funcdata& fd);
    uint4 executeOnce(Funcdata& fd);

    int4 getNumActions() const { return static_cast<int4>(actions.size()); }
    Action* getAction(int4 index) const;
    const std::string& getName() const { return name; }
    uint4 getFilterCategory() const { return filterCategory; }
    int4 getMaxIterations() const { return maxIterations; }
    void setMaxIterations(int4 val) { maxIterations = val; }
    void setFilterCategory(uint4 cat) { filterCategory = cat; }
};

} // namespace ghidra
