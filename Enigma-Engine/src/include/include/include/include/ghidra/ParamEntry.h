#pragma once

#include <ghidra/AddressSpace.h>
#include <ghidra/Address.h>
#include <ghidra/StorageClass.h>
#include <ghidra/DataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/Pointer.h>
#include <ghidra/AbstractFloatDataType.h>
#include <ghidra/ParameterPieces.h>
#include <ghidra/SpecXmlUtils.h>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

class CompilerSpec;
class Encoder;
class XmlPullParser;

class ParamEntry {
public:
    static const int FORCE_LEFT_JUSTIFY = 1;
    static const int REVERSE_STACK = 2;
    static const int SMALLSIZE_ZEXT = 4;
    static const int SMALLSIZE_SEXT = 8;
    static const int IS_BIG_ENDIAN = 16;
    static const int SMALLSIZE_INTTYPE = 32;
    static const int SMALLSIZE_FLOAT = 64;
    static const int IS_GROUPED = 512;
    static const int OVERLAPPING = 0x100;

    ParamEntry(int grp) {
        groupSet_.push_back(grp);
        flags_ = 0;
        type_ = StorageClass::GENERAL;
        spaceid_ = nullptr;
        addressbase_ = 0;
        size_ = -1;
        minsize_ = -1;
        alignment_ = 0;
        numslots_ = 1;
    }

    int getGroup() const { return groupSet_.empty() ? -1 : groupSet_[0]; }
    const std::vector<int>& getAllGroups() const { return groupSet_; }
    int getSize() const { return size_; }
    int getMinSize() const { return minsize_; }
    int getAlign() const { return alignment_; }
    long getAddressBase() const { return addressbase_; }
    StorageClass getType() const { return type_; }
    bool isExclusion() const { return alignment_ == 0; }
    bool isReverseStack() const { return (flags_ & REVERSE_STACK) != 0; }
    bool isGrouped() const { return (flags_ & IS_GROUPED) != 0; }
    bool isOverlap() const { return (flags_ & OVERLAPPING) != 0; }
    bool isBigEndian() const { return (flags_ & IS_BIG_ENDIAN) != 0; }
    bool isLeftJustified() const {
        return ((flags_ & IS_BIG_ENDIAN) == 0) || ((flags_ & FORCE_LEFT_JUSTIFY) != 0);
    }
    AddressSpace* getSpace() const { return spaceid_; }

    void setSpace(AddressSpace* spc) { spaceid_ = spc; }
    void setAddressBase(long base) { addressbase_ = base; }
    void setSize(int sz) { size_ = sz; }
    void setMinSize(int sz) { minsize_ = sz; }
    void setAlign(int align) { alignment_ = align; }
    void setType(StorageClass t) { type_ = t; }
    void setFlags(int f) { flags_ = f; }
    void setNumSlots(int n) { numslots_ = n; }
    void addGroup(int g) { groupSet_.push_back(g); }

    bool containedBy(const Address& addr, int sz) const {
        if (!spaceid_ || spaceid_ != addr.getAddressSpace()) return false;
        if (addressbase_ < addr.getOffset()) return false;
        long rangeEnd = addr.getOffset() + sz - 1;
        long thisEnd = addressbase_ + size_ - 1;
        return thisEnd <= rangeEnd;
    }

    bool intersects(const Address& addr, int sz) const {
        if (!spaceid_ || spaceid_->getSpaceID() != addr.getAddressSpace()->getSpaceID()) return false;
        long rangeEnd = addr.getOffset() + sz - 1;
        long thisEnd = addressbase_ + size_ - 1;
        if (addr.getOffset() < addressbase_ && rangeEnd < thisEnd) return false;
        if (addr.getOffset() > addressbase_ && rangeEnd > thisEnd) return false;
        return true;
    }

    int justifiedContain(const Address& addr, int sz) const {
        if (alignment_ == 0) {
            return justifiedContainAddress(spaceid_, addressbase_, size_,
                addr.getAddressSpace(), addr.getOffset(), sz,
                (flags_ & FORCE_LEFT_JUSTIFY) != 0,
                (flags_ & IS_BIG_ENDIAN) != 0);
        }
        if (spaceid_ != addr.getAddressSpace()) return -1;
        long startaddr = addr.getOffset();
        if (startaddr < addressbase_) return -1;
        long endaddr = startaddr + sz - 1;
        if (endaddr < startaddr) return -1;
        if (addressbase_ + size_ - 1 < endaddr) return -1;
        startaddr -= addressbase_;
        endaddr -= addressbase_;
        if (!isLeftJustified()) {
            int res = static_cast<int>((endaddr + 1) % alignment_);
            if (res == 0) return 0;
            return alignment_ - res;
        }
        return static_cast<int>(startaddr % alignment_);
    }

    bool contains(const ParamEntry& otherEntry) const {
        Address addr(spaceid_, addressbase_);
        return otherEntry.containedBy(addr, size_);
    }

    int getSlot(const Address& addr, int skip) const {
        int res = groupSet_.empty() ? 0 : groupSet_[0];
        if (alignment_ != 0) {
            long diff = addr.getOffset() + skip - addressbase_;
            int baseslot = static_cast<int>(diff / alignment_);
            if (isReverseStack()) {
                res += (numslots_ - 1) - baseslot;
            } else {
                res += baseslot;
            }
        } else if (skip != 0) {
            res = groupSet_.empty() ? 0 : groupSet_.back();
        }
        return res;
    }

    int getAddrBySlot(int slotnum, int sz, int typeAlign, ParameterPieces& res) {
        return getAddrBySlot(slotnum, sz, typeAlign, res, !isLeftJustified());
    }

    int getAddrBySlot(int slotnum, int sz, int typeAlign, ParameterPieces& res, bool justifyRight) {
        int spaceused;
        long offset;
        res.address = Address::NO_ADDRESS;
        if (sz < minsize_) return slotnum;
        if (alignment_ == 0) {
            if (slotnum != 0) return slotnum;
            if (sz > size_) return slotnum;
            offset = addressbase_;
            spaceused = size_;
        } else {
            if (typeAlign > alignment_) {
                int tmp = (slotnum * alignment_) % typeAlign;
                if (tmp != 0) {
                    slotnum += (typeAlign - tmp) / alignment_;
                }
            }
            int slotsused = sz / alignment_;
            if ((sz % alignment_) != 0) slotsused += 1;
            if (slotnum + slotsused > numslots_) return slotnum;
            spaceused = slotsused * alignment_;
            int index;
            if (isReverseStack()) {
                index = numslots_ - slotnum - slotsused;
            } else {
                index = slotnum;
            }
            offset = addressbase_ + index * alignment_;
            slotnum += slotsused;
        }
        if (justifyRight) offset += (spaceused - sz);
        res.address = Address(spaceid_, offset);
        return slotnum;
    }

    bool isEquivalent(const ParamEntry& obj) const {
        if (spaceid_ != obj.spaceid_ || addressbase_ != obj.addressbase_) return false;
        if (size_ != obj.size_ || minsize_ != obj.minsize_ || alignment_ != obj.alignment_) return false;
        if (type_ != obj.type_ || flags_ != obj.flags_) return false;
        if (numslots_ != obj.numslots_) return false;
        if (groupSet_.size() != obj.groupSet_.size()) return false;
        for (size_t i = 0; i < groupSet_.size(); ++i) {
            if (groupSet_[i] != obj.groupSet_[i]) return false;
        }
        return true;
    }

    static int justifiedContainAddress(AddressSpace* spc1, long offset1, int sz1,
                                        AddressSpace* spc2, long offset2, int sz2,
                                        bool forceleft, bool isBigEndian) {
        if (spc1 != spc2) return -1;
        if (offset2 < offset1) return -1;
        long off1 = offset1 + (sz1 - 1);
        long off2 = offset2 + (sz2 - 1);
        if (off1 < off2) return -1;
        if (isBigEndian && !forceleft) return static_cast<int>(off1 - off2);
        return static_cast<int>(offset2 - offset1);
    }

    static StorageClass getBasicTypeClass(DataType* tp) {
        TypeDef* td = dynamic_cast<TypeDef*>(tp);
        if (td) {
            tp = td->getBaseDataType();
        }
        if (dynamic_cast<AbstractFloatDataType*>(tp)) return StorageClass::FLOAT;
        if (dynamic_cast<Pointer*>(tp)) return StorageClass::PTR;
        return StorageClass::GENERAL;
    }

    static void orderWithinGroup(ParamEntry& entry1, ParamEntry& entry2) {
        if (entry2.minsize_ > entry1.size_ || entry1.minsize_ > entry2.size_) return;
        if (entry1.type_ != entry2.type_) {
            if (entry1.type_ == StorageClass::GENERAL) {
                throw std::runtime_error("<pentry> tags with a specific type must come before the general type");
            }
            return;
        }
        throw std::runtime_error("<pentry> tags within a group must be distinguished by size or type");
    }

    void encode(class Encoder& encoder) {
        // Stub
    }

    void restoreXml(class XmlPullParser& parser, CompilerSpec& cspec,
                    std::vector<ParamEntry>& curList, bool grouped) {
        // Stub
    }

private:
    int flags_;
    StorageClass type_;
    std::vector<int> groupSet_;
    AddressSpace* spaceid_;
    long addressbase_;
    int size_;
    int minsize_;
    int alignment_;
    int numslots_;
};

} // namespace ghidra
