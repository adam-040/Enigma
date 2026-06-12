#include <ghidra/Action.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOpAST.h>
#include <algorithm>
#include <iostream>

namespace ghidra {

Action::Action(const std::string& nm, uint4 cat, const std::string& cmt)
    : name(nm), comment(cmt), category(cat), enabled(true), applyCount(0) {
}

ActionList::ActionList(const std::string& nm, uint4 filter, int4 maxIter)
    : name(nm), filterCategory(filter), maxIterations(maxIter) {
}

ActionList::~ActionList() {
    clear();
}

void ActionList::addAction(Action* action) {
    if (action) actions.push_back(action);
}

void ActionList::removeAction(Action* action) {
    auto it = std::find(actions.begin(), actions.end(), action);
    if (it != actions.end()) {
        delete *it;
        actions.erase(it);
    }
}

void ActionList::clear() {
    for (auto* action : actions) {
        delete action;
    }
    actions.clear();
}

uint4 ActionList::execute(Funcdata& fd) {
    uint4 totalStatus = Action::STATUS_NONE;
    int4 iterations = 0;

    do {
        uint4 iterStatus = executeOnce(fd);
        totalStatus |= iterStatus;
        iterations++;
        if ((iterStatus & Action::STATUS_BREAK) != 0) break;
    } while ((totalStatus & Action::STATUS_REPEAT) != 0 && iterations < maxIterations);

    return totalStatus;
}

uint4 ActionList::executeOnce(Funcdata& fd) {
    uint4 totalStatus = Action::STATUS_NONE;

    for (auto* action : actions) {
        if (!action->isEnabled()) continue;
        if ((action->getCategory() & filterCategory) == 0) continue;

        uint4 status = action->apply(fd);
        totalStatus |= status;

        if ((status & Action::STATUS_BREAK) != 0) break;
    }

    return totalStatus;
}

Action* ActionList::getAction(int4 index) const {
    if (index >= 0 && index < static_cast<int4>(actions.size())) {
        return actions[index];
    }
    return nullptr;
}

} // namespace ghidra
