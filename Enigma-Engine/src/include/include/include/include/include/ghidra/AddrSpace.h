#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Types.h>
#include <string>
#include <vector>

namespace ghidra {

class AddrSpaceManager {
private:
    std::vector<AddressSpace*> spaceList;
    AddressSpace* defaultSpace;
    AddressSpace* codeSpace;
    AddressSpace* dataSpace;
    AddressSpace* constantSpace;
    AddressSpace* uniqueSpace;
    AddressSpace* registerSpace;
    int4 numSpaces;
    bool m_bigEndian;
    int4 defaultPointerSize;

public:
    AddrSpaceManager();
    ~AddrSpaceManager();

    AddressSpace* addSpace(const std::string& name, int type, int4 pointerSize,
                           int4 addressableUnitSize = 1, bool isLoad = true);
    AddressSpace* getSpace(int4 index) const;
    AddressSpace* getSpace(const std::string& name) const;
    AddressSpace* getSpaceByType(int type, int4 minimumIndex = 0) const;
    AddressSpace* getDefaultSpace() const { return defaultSpace; }
    AddressSpace* getCodeSpace() const { return codeSpace; }
    AddressSpace* getDataSpace() const { return dataSpace; }
    AddressSpace* getConstantSpace() const { return constantSpace; }
    AddressSpace* getUniqueSpace() const { return uniqueSpace; }
    AddressSpace* getRegisterSpace() const { return registerSpace; }

    int4 getNumSpaces() const { return numSpaces; }
    bool isBigEndian() const { return m_bigEndian; }
    int4 getDefaultPointerSize() const { return defaultPointerSize; }

    void setDefaultSpace(AddressSpace* space);
    void setCodeSpace(AddressSpace* space);
    void setDataSpace(AddressSpace* space);
    void setBigEndian(bool val) { m_bigEndian = val; }
    void setDefaultPointerSize(int4 size) { defaultPointerSize = size; }

    Address translateAddress(const Address& addr) const;
    Address getStackSpaceOffset(const Address& addr, int4 stackPtrSize) const;
};

} // namespace ghidra
