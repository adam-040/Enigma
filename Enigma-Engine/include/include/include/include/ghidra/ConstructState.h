#pragma once

#include <vector>
#include <string>
#include <memory>
#include <sstream>

namespace ghidra {

class Constructor;

class ConstructState {
public:
    ConstructState(ConstructState* parent = nullptr);

    ConstructState* getSubState(int index) const {
        return resolvedStates[index];
    }

    int getNumSubStates() const {
        return static_cast<int>(resolvedStates.size());
    }

    void addSubState(ConstructState* opState) {
        resolvedStates.push_back(opState);
    }

    ConstructState* getParent() const {
        return parent;
    }

    int hashCode() const {
        return computeHashCode(0x56c93c59);
    }

    Constructor* getConstructor() const {
        return ct;
    }

    void setConstructor(Constructor* constructor) {
        ct = constructor;
    }

    int getLength() const {
        return length;
    }

    void setLength(int len) {
        length = len;
    }

    int getOffset() const {
        return offset;
    }

    void setOffset(int off) {
        offset = off;
    }

    std::string dumpConstructorTree() const;

private:
    int computeHashCode(int hashcode) const;

    Constructor* ct = nullptr;
    std::vector<ConstructState*> resolvedStates;
    ConstructState* parent = nullptr;
    int length = 0;
    int offset = 0;
};

} // namespace ghidra
