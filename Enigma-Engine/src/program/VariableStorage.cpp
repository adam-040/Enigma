#include <ghidra/VariableStorage.h>
#include <ghidra/Program.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Language.h>
#include <stdexcept>
#include <sstream>
#include <algorithm>

namespace ghidra {

const VariableStorage VariableStorage::BAD_STORAGE(StorageType::BAD);
const VariableStorage VariableStorage::UNASSIGNED_STORAGE(StorageType::UNASSIGNED);
const VariableStorage VariableStorage::VOID_STORAGE(StorageType::VOID);

VariableStorage::VariableStorage() : type_(StorageType::UNASSIGNED) {}

VariableStorage::VariableStorage(StorageType type) : type_(type) {}

VariableStorage::VariableStorage(Program* program, const std::vector<Varnode>& varnodes)
    : type_(StorageType::MAPPED), varnodes_(varnodes), program_(program) {
    checkVarnodes();
}

VariableStorage::VariableStorage(Program* program, const std::vector<Register*>& registers)
    : type_(StorageType::MAPPED), program_(program) {
    varnodes_.reserve(registers.size());
    for (Register* r : registers) {
        if (r) {
            varnodes_.push_back(Varnode(r->getAddress(), r->getMinimumByteSize()));
        }
    }
    checkVarnodes();
}

VariableStorage::VariableStorage(Program* program, int stackOffset, int size)
    : type_(StorageType::MAPPED), program_(program) {
    if (program && program->getAddressFactory()) {
        const AddressSpace* stackSpace = program->getAddressFactory()->getStackSpace();
        Address addr(const_cast<AddressSpace*>(stackSpace), stackOffset);
        varnodes_.push_back(Varnode(addr, size));
    } else {
        varnodes_.push_back(Varnode(Address(), size));
    }
    checkVarnodes();
}

VariableStorage::VariableStorage(Program* program, Address address, int size)
    : type_(StorageType::MAPPED), program_(program) {
    varnodes_.push_back(Varnode(address, size));
    checkVarnodes();
}

void VariableStorage::checkVarnodes() {
    if (varnodes_.empty()) {
        throw std::invalid_argument("A minimum of one varnode must be specified");
    }
    size_ = 0;
    for (size_t i = 0; i < varnodes_.size(); ++i) {
        const Varnode& varnode = varnodes_[i];
        if (varnode.getSize() <= 0) {
            throw std::invalid_argument("Unsupported varnode size");
        }
        Address storageAddr = varnode.getAddress();
        bool isRegister = false;
        if (storageAddr.isHashAddress() || storageAddr.isUniqueAddress() || storageAddr.isConstantAddress()) {
            if (varnodes_.size() != 1) {
                throw std::runtime_error("Hash, Unique and Constant storage may only use a single varnode");
            }
        } else {
            if (program_ && program_->getAddressFactory()) {
                const AddressSpace* space = program_->getAddressFactory()->getAddressSpace(varnode.getSpace());
                const AddressSpace* varnodeSpace = varnode.getAddress().getAddressSpace();
                if (space != varnodeSpace) {
                    throw std::runtime_error("Invalid varnode address for specified program");
                }
            }
        }

        if (program_ && !storageAddr.isStackAddress()) {
            Register* reg = program_->getRegister(storageAddr, varnode.getSize());
            if (reg) {
                isRegister = true;
                registers_.push_back(reg);
            }
        } else if (storageAddr.isStackAddress()) {
            long stackOffset = storageAddr.getOffset();
            if (stackOffset < 0 && -stackOffset < varnode.getSize()) {
                throw std::runtime_error("Stack varnode violates stack frame constraints");
            }
        }

        bool isBigEndian = (program_ && program_->getLanguage() && program_->getLanguage()->isBigEndian());
        if (isBigEndian) {
            if (i < (varnodes_.size() - 1) && !isRegister) {
                throw std::runtime_error("Compound storage must use registers except for last BE varnode");
            }
        } else {
            if (i > 0 && !isRegister) {
                throw std::runtime_error("Compound storage must use registers except for first LE varnode");
            }
        }
        size_ += varnode.getSize();
    }

    for (size_t i = 0; i < varnodes_.size(); ++i) {
        for (size_t j = i + 1; j < varnodes_.size(); ++j) {
            if (varnodes_[i].intersects(varnodes_[j])) {
                throw std::runtime_error("One or more conflicting storage varnodes");
            }
        }
    }
}

int VariableStorage::getVarnodeCount() const {
    return varnodes_.size();
}

std::vector<Varnode> VariableStorage::getVarnodes() const {
    return varnodes_;
}

Varnode VariableStorage::getFirstVarnode() const {
    return varnodes_.empty() ? Varnode(Address(), 0) : varnodes_[0];
}

Varnode VariableStorage::getLastVarnode() const {
    return varnodes_.empty() ? Varnode(Address(), 0) : varnodes_.back();
}

bool VariableStorage::isStackStorage() const {
    if (varnodes_.size() != 1) return false;
    return varnodes_[0].getAddress().isStackAddress();
}

bool VariableStorage::hasStackStorage() const {
    if (varnodes_.empty()) return false;
    if (varnodes_[0].getAddress().isStackAddress()) return true;
    if (varnodes_.size() == 1) return false;
    return varnodes_.back().getAddress().isStackAddress();
}

bool VariableStorage::isRegisterStorage() const {
    return varnodes_.size() == 1 && !registers_.empty();
}

Register* VariableStorage::getRegister() const {
    return registers_.empty() ? nullptr : registers_[0];
}

std::vector<Register*> VariableStorage::getRegisters() const {
    return registers_;
}

long VariableStorage::getRegisterOffset(Register* reg) const {
    if (!reg) return -1;
    Address regAddrMin = reg->getAddress();
    Address regAddrMax = regAddrMin.add(reg->getMinimumByteSize() - 1);
    long offset = 0;
    bool isBigEndian = (program_ && program_->getLanguage() && program_->getLanguage()->isBigEndian());
    if (isBigEndian) {
        for (size_t i = 0; i < varnodes_.size(); i++) {
            const Varnode& varnode = varnodes_[i];
            if (varnode.isRegister() && varnode.contains(regAddrMin) && varnode.contains(regAddrMax)) {
                return offset + (regAddrMin.subtract(varnode.getAddress()));
            }
            offset += varnode.getSize();
        }
    } else {
        for (int i = (int)varnodes_.size() - 1; i >= 0; i--) {
            const Varnode& varnode = varnodes_[i];
            if (varnode.isRegister() && varnode.contains(regAddrMin) && varnode.contains(regAddrMax)) {
                long varnodeEndOffset = varnode.getAddress().getOffset() + (varnode.getSize() - 1);
                return offset + (varnodeEndOffset - regAddrMax.getOffset());
            }
            offset += varnode.getSize();
        }
    }
    return -1;
}

int VariableStorage::getStackOffset() const {
    if (!varnodes_.empty()) {
        Address storageAddr = getFirstVarnode().getAddress();
        if (storageAddr.isStackAddress()) {
            return (int)storageAddr.getOffset();
        }
        if (varnodes_.size() > 1) {
            storageAddr = getLastVarnode().getAddress();
            if (storageAddr.isStackAddress()) {
                return (int)storageAddr.getOffset();
            }
        }
    }
    throw std::runtime_error("Storage does not have a stack varnode");
}

Address VariableStorage::getMinAddress() const {
    if (varnodes_.empty()) return Address();
    return varnodes_[0].getAddress();
}

bool VariableStorage::isMemoryStorage() const {
    if (varnodes_.empty()) return false;
    Address storageAddr = varnodes_[0].getAddress();
    return storageAddr.isMemoryAddress() && registers_.empty();
}

bool VariableStorage::isConstantStorage() const {
    if (varnodes_.empty()) return false;
    return varnodes_[0].getAddress().isConstantAddress();
}

bool VariableStorage::isHashStorage() const {
    if (varnodes_.empty()) return false;
    return varnodes_[0].getAddress().isHashAddress();
}

bool VariableStorage::isUniqueStorage() const {
    if (varnodes_.empty()) return false;
    return varnodes_[0].getAddress().isUniqueAddress();
}

bool VariableStorage::isCompoundStorage() const {
    return varnodes_.size() > 1;
}

bool VariableStorage::isAutoStorage() const { return false; }
AutoParameterType VariableStorage::getAutoParameterType() const { return AutoParameterType::THIS; }
bool VariableStorage::isForcedIndirect() const { return false; }

bool VariableStorage::contains(Address address) const {
    for (const auto& varnode : varnodes_) {
        if (varnode.contains(address)) return true;
    }
    return false;
}

bool VariableStorage::intersects(const VariableStorage& other) const {
    for (const auto& v1 : varnodes_) {
        for (const auto& v2 : other.varnodes_) {
            if (v1.intersects(v2)) return true;
        }
    }
    return false;
}

bool VariableStorage::intersects(const AddressSetView& set) const {
    if (varnodes_.empty() || set.isEmpty()) return false;
    for (const auto& varnode : varnodes_) {
        Address start = varnode.getAddress();
        Address end = start.add(varnode.getSize() - 1);
        if (set.intersects(start, end)) return true;
    }
    return false;
}

bool VariableStorage::intersects(Register* reg) const {
    if (!reg) return false;
    Varnode regVarnode(reg->getAddress(), reg->getMinimumByteSize());
    for (const auto& varnode : varnodes_) {
        if (varnode.intersects(regVarnode)) return true;
    }
    return false;
}

int VariableStorage::compareTo(const VariableStorage& other) const {
    auto getPrecedence = [](const VariableStorage& s) {
        if (s.isUnassignedStorage()) return 2;
        if (!s.varnodes_.empty()) return 1;
        return 3;
    };
    int myPrec = getPrecedence(*this);
    int otherPrec = getPrecedence(other);
    int diff = myPrec - otherPrec;
    if (diff != 0 || myPrec != 1) {
        return diff;
    }
    size_t compareCnt = std::min(varnodes_.size(), other.varnodes_.size());
    for (size_t i = 0; i < compareCnt; ++i) {
        Address myAddr = varnodes_[i].getAddress();
        Address otherAddr = other.varnodes_[i].getAddress();
        diff = myAddr.compareTo(otherAddr);
        if (diff != 0) return diff;
        diff = varnodes_[i].getSize() - other.varnodes_[i].getSize();
        if (diff != 0) return diff;
    }
    return (int)varnodes_.size() - (int)other.varnodes_.size();
}

std::string VariableStorage::getSerializationString() const {
    if (!serialization_.empty()) return serialization_;
    if (isBadStorage()) {
        serialization_ = "<BAD>";
    } else if (isUnassignedStorage()) {
        serialization_ = "<UNASSIGNED>";
    } else if (isVoidStorage()) {
        serialization_ = "<VOID>";
    } else {
        serialization_ = getSerializationString(varnodes_);
    }
    return serialization_;
}

std::string VariableStorage::toString() const {
    if (isBadStorage()) return "<BAD>";
    if (isUnassignedStorage()) return "<UNASSIGNED>";
    if (isVoidStorage()) return "<VOID>";
    std::string result;
    for (size_t i = 0; i < varnodes_.size(); ++i) {
        if (i > 0) result += ",";
        Address addr = varnodes_[i].getAddress();
        int sz = varnodes_[i].getSize();
        Register* reg = nullptr;
        if ((addr.isRegisterAddress() || addr.isMemoryAddress()) && program_) {
            reg = program_->getRegister(addr, sz);
        }
        if (reg) {
            result += reg->getName();
        } else {
            result += addr.toString();
        }
        result += ":" + std::to_string(sz);
    }
    return result;
}

bool VariableStorage::operator==(const VariableStorage& other) const {
    if (isAutoStorage() != other.isAutoStorage()) return false;
    if (isForcedIndirect() != other.isForcedIndirect()) return false;
    if (isBadStorage() != other.isBadStorage()) return false;
    if (isUnassignedStorage() != other.isUnassignedStorage()) return false;
    if (isVoidStorage() != other.isVoidStorage()) return false;
    return compareTo(other) == 0;
}

bool VariableStorage::operator<(const VariableStorage& other) const {
    return compareTo(other) < 0;
}

std::string VariableStorage::getSerializationString(const std::vector<Varnode>& varnodes) {
    if (varnodes.empty()) {
        throw std::invalid_argument("varnodes may not be empty");
    }
    std::string result;
    for (const auto& v : varnodes) {
        if (!result.empty()) result += ",";
        result += v.getAddress().toString(true) + ":" + std::to_string(v.getSize());
    }
    return result;
}

VariableStorage VariableStorage::deserialize(Program* program, const std::string& serialization) {
    if (serialization.empty() || serialization == "<UNASSIGNED>") {
        return UNASSIGNED_STORAGE;
    }
    if (serialization == "<VOID>") {
        return VOID_STORAGE;
    }
    if (serialization == "<BAD>") {
        return BAD_STORAGE;
    }
    try {
        std::vector<Varnode> vlist = getVarnodes(program, serialization);
        if (vlist.empty()) return BAD_STORAGE;
        return VariableStorage(program, vlist);
    } catch (...) {
        return BAD_STORAGE;
    }
}

std::vector<Varnode> VariableStorage::getVarnodes(Program* program, const std::string& serialization) {
    std::vector<Varnode> list;
    if (serialization == "<BAD>" || serialization.empty()) {
        return list;
    }
    if (!program || !program->getAddressFactory()) {
        return list;
    }
    std::stringstream ss(serialization);
    std::string item;
    while (std::getline(ss, item, ',')) {
        size_t idx = item.rfind(':');
        if (idx == std::string::npos || idx == 0) {
            list.clear();
            break;
        }
        std::string addrStr = item.substr(0, idx);
        std::string sizeStr = item.substr(idx + 1);
        auto addrOpt = program->getAddressFactory()->getAddress(addrStr);
        if (!addrOpt.has_value() || !addrOpt.value().isValid()) {
            list.clear();
            break;
        }
        int size = std::stoi(sizeStr);
        list.push_back(Varnode(addrOpt.value(), size));
    }
    return list;
}

} // namespace ghidra
