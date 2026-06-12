#pragma once

#include <ghidra/Address.h>
#include <string>

namespace ghidra {

class MemoryBlockDefinition {
public:
    MemoryBlockDefinition() = default;
    MemoryBlockDefinition(const std::string& name, const std::string& addressStr,
                          int length, bool initialized, bool overlay,
                          bool readPerm, bool writePerm, bool execPerm, bool isVolatile)
        : blockName_(name), addressString_(addressStr), length_(length),
          initialized_(initialized), overlay_(overlay),
          readPermission_(readPerm), writePermission_(writePerm),
          executePermission_(execPerm), isVolatile_(isVolatile) {}

    const std::string& getBlockName() const { return blockName_; }
    const std::string& getAddressString() const { return addressString_; }
    int getLength() const { return length_; }
    bool isInitialized() const { return initialized_; }
    bool isOverlay() const { return overlay_; }
    bool isRead() const { return readPermission_; }
    bool isWrite() const { return writePermission_; }
    bool isExecute() const { return executePermission_; }
    bool isVolatile() const { return isVolatile_; }

private:
    std::string blockName_;
    std::string addressString_;
    int length_ = 0;
    bool initialized_ = true;
    bool overlay_ = false;
    bool readPermission_ = true;
    bool writePermission_ = true;
    bool executePermission_ = true;
    bool isVolatile_ = false;
};

} // namespace ghidra
