#pragma once

#include <ghidra/DataTypePath.h>
#include <ghidra/CategoryPath.h>

namespace ghidra {

class DataType;
class DataTypeManager;
class SourceArchive;

class DataTypeManagerChangeListener {
public:
    virtual ~DataTypeManagerChangeListener() = default;

    virtual void categoryAdded(DataTypeManager* dtm, const CategoryPath& path) = 0;
    virtual void categoryRemoved(DataTypeManager* dtm, const CategoryPath& path) = 0;
    virtual void categoryRenamed(DataTypeManager* dtm, const CategoryPath& oldPath, const CategoryPath& newPath) = 0;
    virtual void categoryMoved(DataTypeManager* dtm, const CategoryPath& oldPath, const CategoryPath& newPath) = 0;

    virtual void dataTypeAdded(DataTypeManager* dtm, const DataTypePath& path) = 0;
    virtual void dataTypeRemoved(DataTypeManager* dtm, const DataTypePath& path) = 0;
    virtual void dataTypeRenamed(DataTypeManager* dtm, const DataTypePath& oldPath, const DataTypePath& newPath) = 0;
    virtual void dataTypeMoved(DataTypeManager* dtm, const DataTypePath& oldPath, const DataTypePath& newPath) = 0;
    virtual void dataTypeChanged(DataTypeManager* dtm, const DataTypePath& path) = 0;
    virtual void dataTypeReplaced(DataTypeManager* dtm, const DataTypePath& oldPath, const DataTypePath& newPath, DataType* newDataType) = 0;

    virtual void favoritesChanged(DataTypeManager* dtm, const DataTypePath& path, bool isFavorite) = 0;
    virtual void sourceArchiveChanged(DataTypeManager* dataTypeManager, SourceArchive* sourceArchive) = 0;
    virtual void sourceArchiveAdded(DataTypeManager* dataTypeManager, SourceArchive* sourceArchive) = 0;
    virtual void programArchitectureChanged(DataTypeManager* dataTypeManager) = 0;
    virtual void restored(DataTypeManager* dataTypeManager) = 0;
};

} // namespace ghidra
