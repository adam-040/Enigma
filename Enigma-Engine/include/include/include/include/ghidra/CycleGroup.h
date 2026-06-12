/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CycleGroup.h
/// \brief A set of data types that a single action can cycle through.
#pragma once

#include "ghidra/DataType.h"
#include <string>
#include <vector>

namespace ghidra {

class DataType;
class Pointer;

class CycleGroup {
public:
    CycleGroup(const std::string& name);
    CycleGroup(const std::string& name, const std::vector<DataType*>& dataTypes, int keyCode = 0);
    CycleGroup(const std::string& name, DataType* dt, int keyCode = 0);

    std::string getName() const { return name_; }
    int getDefaultKeyCode() const { return keyCode_; }
    int size() const { return static_cast<int>(dataList_.size()); }
    std::vector<DataType*> getDataTypes() const { return dataList_; }

    void addDataType(DataType* dt);
    void addFirst(DataType* dt);
    void removeDataType(DataType* dt);
    void removeFirst();
    void removeLast();
    bool contains(DataType* dt) const;

    DataType* getNextDataType(DataType* currentDataType, bool stackPointers);

    static CycleGroup* getByteCycleGroup();
    static CycleGroup* getFloatCycleGroup();
    static CycleGroup* getStringCycleGroup();
    static const std::vector<CycleGroup*>& getAllCycleGroups();

private:
    bool exists(DataType* dt) const;

    std::string name_;
    std::vector<DataType*> dataList_;
    int keyCode_ = 0;
};

} // namespace ghidra
