/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManagerChangeListenerAdapter.h
/// \brief No-op base class for DataTypeManagerChangeListener.
/// Translated from: ghidra.program.model.data.DataTypeManagerChangeListenerAdapter
#pragma once

#include "ghidra/DataTypeManagerChangeListener.h"

namespace ghidra {

class DataTypeManagerChangeListenerAdapter : public DataTypeManagerChangeListener {
public:
    void categoryAdded(DataTypeManager* dtm, const CategoryPath& path) override {}
    void categoryRemoved(DataTypeManager* dtm, const CategoryPath& path) override {}
    void categoryRenamed(DataTypeManager* dtm,
                         const CategoryPath& oldPath,
                         const CategoryPath& newPath) override {}
    void categoryMoved(DataTypeManager* dtm,
                       const CategoryPath& oldPath,
                       const CategoryPath& newPath) override {}

    void dataTypeAdded(DataTypeManager* dtm, const DataTypePath& path) override {}
    void dataTypeRemoved(DataTypeManager* dtm, const DataTypePath& path) override {}
    void dataTypeRenamed(DataTypeManager* dtm,
                         const DataTypePath& oldPath,
                         const DataTypePath& newPath) override {}
    void dataTypeMoved(DataTypeManager* dtm,
                       const DataTypePath& oldPath,
                       const DataTypePath& newPath) override {}
    void dataTypeChanged(DataTypeManager* dtm, const DataTypePath& path) override {}
    void dataTypeReplaced(DataTypeManager* dtm,
                          const DataTypePath& oldPath,
                          const DataTypePath& newPath,
                          DataType* newDataType) override {}

    void favoritesChanged(DataTypeManager* dtm, const DataTypePath& path, bool isFavorite) override {}
    void sourceArchiveChanged(DataTypeManager* dtm, SourceArchive* sourceArchive) override {}
    void sourceArchiveAdded(DataTypeManager* dtm, SourceArchive* sourceArchive) override {}
    void programArchitectureChanged(DataTypeManager* dtm) override {}
    void restored(DataTypeManager* dtm) override {}
};

} // namespace ghidra
