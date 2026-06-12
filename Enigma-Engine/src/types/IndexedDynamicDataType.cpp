#include <ghidra/IndexedDynamicDataType.h>
#include <ghidra/DataTypeInstance.h>
#include <ghidra/ReadOnlyDataTypeComponent.h>
#include <ghidra/MemoryBufferImpl.h>
#include <ghidra/Memory.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/Settings.h>
#include <iostream>

namespace ghidra {

const std::string IndexedDynamicDataType::NULL_BODY_DESCRIPTION = "NullBody";

IndexedDynamicDataType::IndexedDynamicDataType(const std::string& name, const std::string& description,
                       DataType* header, const std::vector<int64_t>& keys,
                       const std::vector<DataType*>& structs,
                       int64_t indexOffset, int indexSize, int64_t mask, DataTypeManager* dtm)
    : DynamicDataType(name, dtm), description_(description), header_(header),
      keys_(keys), structs_(structs), indexOffset_(indexOffset), indexSize_(indexSize), mask_(mask) {
    
    if (keys_.size() != structs_.size()) {
        std::cerr << "ERROR: keys.length must equal structs.length\n";
    }

    for (size_t i = 0; i < keys_.size(); i++) {
        table_[keys_[i]] = static_cast<int>(i);
    }
    if (mask_ == 0) {
        mask_ = 0xFFFFFFFF;
    }
}

IndexedDynamicDataType::IndexedDynamicDataType(const std::string& name, const std::string& description,
                       DataType* header, int64_t singleKey,
                       DataType* structIfSingle, DataType* structIfDefault,
                       int64_t indexOffset, int indexSize, int64_t mask, DataTypeManager* dtm)
    : DynamicDataType(name, dtm), description_(description), header_(header),
      indexOffset_(indexOffset), indexSize_(indexSize), mask_(mask) {
    
    keys_.push_back(singleKey);
    structs_.push_back(structIfSingle);
    if (structIfDefault) structs_.push_back(structIfDefault);

    if (mask_ == 0) {
        mask_ = 0xFFFFFFFF;
    }
    // For single key, we don't strictly need table_, but keeping it consistent
    for (size_t i = 0; i < structs_.size(); i++) {
        table_[i] = static_cast<int>(i);
    }
}

std::vector<DataTypeComponent*> IndexedDynamicDataType::getAllComponents(MemBuffer* buf) {
    Memory* memory = buf->getMemory();
    if (!memory) return {};

    Address start = buf->getAddress();
    
    // Find index
    Address loc = start.addWrap(indexOffset_);
    int64_t index = 0;
    try {
        switch (indexSize_) {
            case 1: index = static_cast<uint8_t>(memory->getByte(loc)); break;
            case 2: index = static_cast<uint16_t>(memory->getShort(loc)); break;
            case 4: index = static_cast<uint32_t>(memory->getInt(loc)); break;
            case 8: index = memory->getLong(loc); break;
            default: return {};
        }
    } catch (const MemoryAccessException&) {
        return {};
    }

    index &= mask_;

    int structIndex = -1;
    if (keys_.size() == 1) {
        structIndex = (index == keys_[0]) ? 0 : 1;
    } else {
        auto it = table_.find(index);
        if (it != table_.end()) {
            structIndex = it->second;
        }
    }

    if (structIndex < 0 || structIndex >= static_cast<int>(structs_.size())) {
        return {};
    }

    DataType* data = structs_[structIndex];
    if (!data) return {};

    std::vector<DataTypeComponent*> comps;
    if (data->getDescription() == NULL_BODY_DESCRIPTION) {
        comps.resize(1, nullptr);
    } else {
        comps.resize(2, nullptr);
    }

    MemoryBufferImpl newBuf(memory, start);
    DataTypeInstance* dti = DataTypeInstance::getDataTypeInstance(header_, &newBuf, false);
    if (!dti) {
        std::cerr << "IndexedDynamicDataType: problem with data at " << start.toString() << "\n";
        return {};
    }

    int len = dti->getLength();
    comps[0] = new ReadOnlyDataTypeComponent(header_, this, len, 0, 0, dti->getDataType()->getName(), "");
    delete dti;

    if (comps.size() > 1) {
        try {
            int countSize = len;
            int offset = countSize;
            MemoryBufferImpl nextBuf(memory, start);
            nextBuf.advance(countSize);
            DataTypeInstance* dti2 = DataTypeInstance::getDataTypeInstance(data, &nextBuf, false);
            if (!dti2) {
                std::cerr << "IndexedDynamicDataType: problem with data at " << nextBuf.getAddress().toString() << "\n";
                // leak comps[0]... in a real system we should use unique_ptr. Here we'll just ignore for now or clean up.
                delete comps[0];
                return {};
            }
            int len2 = dti2->getLength();
            std::string compName = dti2->getDataType()->getName() + "_" + nextBuf.getAddress().toString();
            comps[1] = new ReadOnlyDataTypeComponent(dti2->getDataType(), this, len2, 1, offset, compName, "");
            delete dti2;
        } catch (const std::exception&) {
            delete comps[0];
            return {};
        }
    }

    return comps;
}

DataType* IndexedDynamicDataType::clone(DataTypeManager* dtm) const {
    if (keys_.size() == 1) {
        DataType* defaultStruct = structs_.size() > 1 ? structs_[1] : nullptr;
        return new IndexedDynamicDataType(getName(), description_, header_, keys_[0],
                                          structs_[0], defaultStruct,
                                          indexOffset_, indexSize_, mask_, dtm);
    }
    return new IndexedDynamicDataType(getName(), description_, header_, keys_, structs_,
                                      indexOffset_, indexSize_, mask_, dtm);
}

std::string IndexedDynamicDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return getName();
}

int IndexedDynamicDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    return getLength();
}

DataType* IndexedDynamicDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

} // namespace ghidra
