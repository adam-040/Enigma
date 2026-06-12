#include <ghidra/AddrSpace.h>
#include <ghidra/AddressSpace.h>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

AddrSpaceManager::AddrSpaceManager()
    : defaultSpace(nullptr), codeSpace(nullptr), dataSpace(nullptr),
      constantSpace(nullptr), uniqueSpace(nullptr), registerSpace(nullptr),
      numSpaces(0), m_bigEndian(false), defaultPointerSize(4) {
}

AddrSpaceManager::~AddrSpaceManager() {
    for (auto* space : spaceList) {
        delete space;
    }
}

AddressSpace* AddrSpaceManager::addSpace(const std::string& name, int type, int4 pointerSize,
                                          int4 addressableUnitSize, bool isLoad) {
    (void)isLoad;
    int bitSize = pointerSize * 8;
    auto* space = new GenericAddressSpace(name, bitSize, type, numSpaces);
    spaceList.push_back(space);
    numSpaces++;

    if (type == AddressSpace::TYPE_CONSTANT && !constantSpace) {
        constantSpace = space;
    }
    if (type == AddressSpace::TYPE_UNIQUE && !uniqueSpace) {
        uniqueSpace = space;
    }
    if (type == AddressSpace::TYPE_REGISTER && !registerSpace) {
        registerSpace = space;
    }

    return space;
}

AddressSpace* AddrSpaceManager::getSpace(int4 index) const {
    if (index >= 0 && index < numSpaces) {
        return spaceList[index];
    }
    return nullptr;
}

AddressSpace* AddrSpaceManager::getSpace(const std::string& name) const {
    for (auto* space : spaceList) {
        if (space->getName() == name) {
            return space;
        }
    }
    return nullptr;
}

AddressSpace* AddrSpaceManager::getSpaceByType(int type, int4 minimumIndex) const {
    for (auto* space : spaceList) {
        if (space->getType() == type && space->getSpaceID() >= minimumIndex) {
            return space;
        }
    }
    return nullptr;
}

void AddrSpaceManager::setDefaultSpace(AddressSpace* space) {
    defaultSpace = space;
}

void AddrSpaceManager::setCodeSpace(AddressSpace* space) {
    codeSpace = space;
}

void AddrSpaceManager::setDataSpace(AddressSpace* space) {
    dataSpace = space;
}

Address AddrSpaceManager::translateAddress(const Address& addr) const {
    if (!addr.getAddressSpace()) return addr;
    AddressSpace* phys = addr.getAddressSpace()->getPhysicalSpace();
    if (phys && phys != addr.getAddressSpace()) {
        return Address(phys, addr.getOffset());
    }
    return addr;
}

Address AddrSpaceManager::getStackSpaceOffset(const Address& addr, int4 stackPtrSize) const {
    (void)stackPtrSize;
    if (!addr.getAddressSpace()) return addr;
    if (addr.getAddressSpace()->isStackSpace()) {
        return addr;
    }
    AddressSpace* spacebase = getSpaceByType(AddressSpace::TYPE_STACK);
    if (spacebase) {
        return Address(spacebase, addr.getOffset());
    }
    return addr;
}

} // namespace ghidra
