/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManagerChangeListenerHandler.cpp
#include "ghidra/DataTypeManagerChangeListenerHandler.h"
#include <algorithm>

namespace ghidra {

void DataTypeManagerChangeListenerHandler::addDataTypeManagerListener(DataTypeManagerChangeListener* l) {
    if (!l) return;
    if (std::find(listeners_.begin(), listeners_.end(), l) == listeners_.end()) {
        listeners_.push_back(l);
    }
}

void DataTypeManagerChangeListenerHandler::removeDataTypeManagerListener(DataTypeManagerChangeListener* l) {
    auto it = std::find(listeners_.begin(), listeners_.end(), l);
    if (it != listeners_.end()) listeners_.erase(it);
}

void DataTypeManagerChangeListenerHandler::categoryAdded(DataTypeManager* dtm, const CategoryPath& path) {
    for (auto* l : listeners_) l->categoryAdded(dtm, path);
}
void DataTypeManagerChangeListenerHandler::categoryRemoved(DataTypeManager* dtm, const CategoryPath& path) {
    for (auto* l : listeners_) l->categoryRemoved(dtm, path);
}
void DataTypeManagerChangeListenerHandler::categoryRenamed(DataTypeManager* dtm,
                                                          const CategoryPath& oldPath,
                                                          const CategoryPath& newPath) {
    for (auto* l : listeners_) l->categoryRenamed(dtm, oldPath, newPath);
}
void DataTypeManagerChangeListenerHandler::categoryMoved(DataTypeManager* dtm,
                                                        const CategoryPath& oldPath,
                                                        const CategoryPath& newPath) {
    for (auto* l : listeners_) l->categoryMoved(dtm, oldPath, newPath);
}
void DataTypeManagerChangeListenerHandler::dataTypeAdded(DataTypeManager* dtm, const DataTypePath& path) {
    for (auto* l : listeners_) l->dataTypeAdded(dtm, path);
}
void DataTypeManagerChangeListenerHandler::dataTypeRemoved(DataTypeManager* dtm, const DataTypePath& path) {
    for (auto* l : listeners_) l->dataTypeRemoved(dtm, path);
}
void DataTypeManagerChangeListenerHandler::dataTypeRenamed(DataTypeManager* dtm,
                                                          const DataTypePath& oldPath,
                                                          const DataTypePath& newPath) {
    for (auto* l : listeners_) {
        l->dataTypeRenamed(dtm, oldPath, newPath);
        l->favoritesChanged(dtm, oldPath, false);
    }
}
void DataTypeManagerChangeListenerHandler::dataTypeMoved(DataTypeManager* dtm,
                                                        const DataTypePath& oldPath,
                                                        const DataTypePath& newPath) {
    for (auto* l : listeners_) l->dataTypeMoved(dtm, oldPath, newPath);
}
void DataTypeManagerChangeListenerHandler::dataTypeChanged(DataTypeManager* dtm, const DataTypePath& path) {
    for (auto* l : listeners_) l->dataTypeChanged(dtm, path);
}
void DataTypeManagerChangeListenerHandler::dataTypeReplaced(DataTypeManager* dtm,
                                                           const DataTypePath& oldPath,
                                                           const DataTypePath& newPath,
                                                           DataType* newDataType) {
    for (auto* l : listeners_) l->dataTypeReplaced(dtm, oldPath, newPath, newDataType);
}
void DataTypeManagerChangeListenerHandler::favoritesChanged(DataTypeManager* dtm, const DataTypePath& path, bool isFavorite) {
    for (auto* l : listeners_) l->favoritesChanged(dtm, path, isFavorite);
}
void DataTypeManagerChangeListenerHandler::sourceArchiveChanged(DataTypeManager* dtm, SourceArchive* sourceArchive) {
    for (auto* l : listeners_) l->sourceArchiveChanged(dtm, sourceArchive);
}
void DataTypeManagerChangeListenerHandler::sourceArchiveAdded(DataTypeManager* dtm, SourceArchive* sourceArchive) {
    for (auto* l : listeners_) l->sourceArchiveAdded(dtm, sourceArchive);
}
void DataTypeManagerChangeListenerHandler::programArchitectureChanged(DataTypeManager* dtm) {
    for (auto* l : listeners_) l->programArchitectureChanged(dtm);
}
void DataTypeManagerChangeListenerHandler::restored(DataTypeManager* dtm) {
    for (auto* l : listeners_) l->restored(dtm);
}

} // namespace ghidra
