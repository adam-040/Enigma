/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManagerChangeListenerHandler.h
/// \brief Synchronous multiplexer for DataTypeManagerChangeListeners.
/// Translated from: ghidra.program.model.data.DataTypeManagerChangeListenerHandler
#pragma once

#include "ghidra/DataTypeManagerChangeListener.h"
#include <vector>

namespace ghidra {

class DataType;

/// Synchronous multiplexer: fan-out DataTypeManagerChangeListener events
/// to a registered listener list. The headless Enigma port dispatches
/// synchronously rather than via SwingUtilities.invokeLater.
class DataTypeManagerChangeListenerHandler : public DataTypeManagerChangeListener {
public:
    DataTypeManagerChangeListenerHandler() = default;

    void addDataTypeManagerListener(DataTypeManagerChangeListener* l);
    void removeDataTypeManagerListener(DataTypeManagerChangeListener* l);

    size_t listenerCount() const { return listeners_.size(); }

    void categoryAdded(DataTypeManager* dtm, const CategoryPath& path) override;
    void categoryRemoved(DataTypeManager* dtm, const CategoryPath& path) override;
    void categoryRenamed(DataTypeManager* dtm,
                         const CategoryPath& oldPath,
                         const CategoryPath& newPath) override;
    void categoryMoved(DataTypeManager* dtm,
                       const CategoryPath& oldPath,
                       const CategoryPath& newPath) override;
    void dataTypeAdded(DataTypeManager* dtm, const DataTypePath& path) override;
    void dataTypeRemoved(DataTypeManager* dtm, const DataTypePath& path) override;
    void dataTypeRenamed(DataTypeManager* dtm,
                         const DataTypePath& oldPath,
                         const DataTypePath& newPath) override;
    void dataTypeMoved(DataTypeManager* dtm,
                       const DataTypePath& oldPath,
                       const DataTypePath& newPath) override;
    void dataTypeChanged(DataTypeManager* dtm, const DataTypePath& path) override;
    void dataTypeReplaced(DataTypeManager* dtm,
                          const DataTypePath& oldPath,
                          const DataTypePath& newPath,
                          DataType* newDataType) override;
    void favoritesChanged(DataTypeManager* dtm, const DataTypePath& path, bool isFavorite) override;
    void sourceArchiveChanged(DataTypeManager* dtm, SourceArchive* sourceArchive) override;
    void sourceArchiveAdded(DataTypeManager* dtm, SourceArchive* sourceArchive) override;
    void programArchitectureChanged(DataTypeManager* dtm) override;
    void restored(DataTypeManager* dtm) override;

private:
    std::vector<DataTypeManagerChangeListener*> listeners_;
};

} // namespace ghidra
