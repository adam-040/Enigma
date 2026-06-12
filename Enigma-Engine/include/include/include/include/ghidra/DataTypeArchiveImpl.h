#pragma once

#include <ghidra/DataTypeArchive.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <memory>

namespace ghidra {

class DataTypeArchiveImpl : public DataTypeArchive {
public:
    DataTypeArchiveImpl(const std::string& name, int pointerSize);
    ~DataTypeArchiveImpl() override = default;

    DataTypeManager* getDataTypeManager() override;
    int getDefaultPointerSize() const override;
    int64_t getCreationDate() const override;
    DataTypeArchiveChangeSet* getChanges() override;
    void invalidate() override;

    DataTypeManagerImpl* getDataTypeManagerImpl() { return &dtm_; }

private:
    DataTypeManagerImpl dtm_;
    int pointerSize_;
    int64_t creationDate_;
};

} // namespace ghidra
