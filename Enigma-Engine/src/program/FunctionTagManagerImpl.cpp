#include <ghidra/FunctionTagManagerImpl.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <algorithm>
#include <iostream>

namespace ghidra {

FunctionTagManagerImpl::FunctionTagManagerImpl(Program* program)
    : program_(program) {}

FunctionTag* FunctionTagManagerImpl::getFunctionTag(const std::string& name) {
    for (const auto& tag : tags_) {
        if (tag->getName() == name) {
            return tag.get();
        }
    }
    return nullptr;
}

FunctionTag* FunctionTagManagerImpl::getFunctionTag(long id) {
    for (const auto& tag : tags_) {
        if (tag->getId() == id) {
            return tag.get();
        }
    }
    return nullptr;
}

std::vector<FunctionTag*> FunctionTagManagerImpl::getAllFunctionTags() {
    std::vector<FunctionTag*> result;
    result.reserve(tags_.size());
    for (const auto& tag : tags_) {
        result.push_back(tag.get());
    }
    return result;
}

bool FunctionTagManagerImpl::isTagAssigned(const std::string& name) {
    auto* funcMgr = program_ ? program_->getFunctionManager() : nullptr;
    if (!program_) {
        std::cout << "[DEBUG isTagAssigned] program_ is null!" << std::endl;
    } else if (!funcMgr) {
        std::cout << "[DEBUG isTagAssigned] funcMgr is null!" << std::endl;
    } else {
        auto iter = funcMgr->getFunctions();
        std::cout << "[DEBUG isTagAssigned] iter.hasNext() = " << iter.hasNext() << std::endl;
        while (iter.hasNext()) {
            auto* func = iter.next();
            if (func) {
                std::cout << "[DEBUG isTagAssigned] func=" << func->getName() << " tags=" << func->getTags().size() << std::endl;
                for (auto* t : func->getTags()) {
                    if (t) {
                        std::cout << "[DEBUG isTagAssigned]   tag=" << t->getName() << std::endl;
                        if (t->getName() == name) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

FunctionTag* FunctionTagManagerImpl::createFunctionTag(const std::string& name, const std::string& comment) {
    FunctionTag* existing = getFunctionTag(name);
    if (existing) {
        return existing;
    }
    long id = nextId_++;
    auto tag = std::make_unique<FunctionTagImpl>(id, name, comment, this);
    FunctionTag* raw = tag.get();
    tags_.push_back(std::move(tag));
    revision_++;
    return raw;
}

int FunctionTagManagerImpl::getUseCount(FunctionTag* tag) {
    if (!tag) return 0;
    int count = 0;
    auto* funcMgr = program_ ? program_->getFunctionManager() : nullptr;
    if (!program_) {
        std::cout << "[DEBUG getUseCount] program_ is null!" << std::endl;
    } else if (!funcMgr) {
        std::cout << "[DEBUG getUseCount] funcMgr is null!" << std::endl;
    } else {
        auto iter = funcMgr->getFunctions();
        std::cout << "[DEBUG getUseCount] iter.hasNext() = " << iter.hasNext() << std::endl;
        while (iter.hasNext()) {
            auto* func = iter.next();
            if (func) {
                std::cout << "[DEBUG getUseCount] func=" << func->getName() << " tagId=" << tag->getId() << std::endl;
                for (auto* t : func->getTags()) {
                    if (t) {
                        std::cout << "[DEBUG getUseCount]   t->getId()=" << t->getId() << " t->getName()=" << t->getName() << std::endl;
                        if (t->getId() == tag->getId()) {
                            count++;
                        }
                    }
                }
            }
        }
    }
    return count;
}

void FunctionTagManagerImpl::removeFunctionTag(long id) {
    // Also remove from any functions
    auto* funcMgr = program_ ? program_->getFunctionManager() : nullptr;
    if (funcMgr) {
        auto iter = funcMgr->getFunctions();
        while (iter.hasNext()) {
            auto* func = iter.next();
            if (func) {
                // Find and remove mapping inside function
                auto tag = getFunctionTag(id);
                if (tag) {
                    func->removeTag(tag->getName());
                }
            }
        }
    }

    tags_.erase(std::remove_if(tags_.begin(), tags_.end(),
        [id](const std::unique_ptr<FunctionTagImpl>& t) { return t->getId() == id; }), tags_.end());
    revision_++;
}

FunctionTag* FunctionTagManagerImpl::addTagWithId(long id, const std::string& name, const std::string& comment) {
    if (id >= nextId_) {
        nextId_ = id + 1;
    }
    auto tag = std::make_unique<FunctionTagImpl>(id, name, comment, this);
    FunctionTag* raw = tag.get();
    tags_.push_back(std::move(tag));
    revision_++;
    return raw;
}

} // namespace ghidra
