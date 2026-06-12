#include <ghidra/DataTypeArchiveImpl.h>
#include <chrono>

namespace ghidra {

DataTypeArchiveImpl::DataTypeArchiveImpl(const std::string& name, int pointerSize)
    : dtm_(name), pointerSize_(pointerSize) {
    auto now = std::chrono::system_clock::now();
    creationDate_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()).count();
}

DataTypeManager* DataTypeArchiveImpl::getDataTypeManager() {
    return &dtm_;
}

int DataTypeArchiveImpl::getDefaultPointerSize() const {
    return pointerSize_;
}

int64_t DataTypeArchiveImpl::getCreationDate() const {
    return creationDate_;
}

DataTypeArchiveChangeSet* DataTypeArchiveImpl::getChanges() {
    return nullptr;
}

void DataTypeArchiveImpl::invalidate() {
    dtm_.clearAllDataTypes();
}

} // namespace ghidra
