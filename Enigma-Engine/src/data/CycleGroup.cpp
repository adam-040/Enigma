/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CycleGroup.cpp
/// \brief A set of data types that a single action can cycle through.
#include "ghidra/CycleGroup.h"
#include "ghidra/Pointer.h"
#include "ghidra/ByteDataType.h"
#include "ghidra/WordDataType.h"
#include "ghidra/DWordDataType.h"
#include "ghidra/QWordDataType.h"
#include "ghidra/FloatDataType.h"
#include "ghidra/DoubleDataType.h"
#include "ghidra/LongDoubleDataType.h"
#include "ghidra/CharDataType.h"
#include "ghidra/StringDataType.h"
#include "ghidra/UnicodeDataType.h"

namespace ghidra {

CycleGroup::CycleGroup(const std::string& name) : name_(name) {}

CycleGroup::CycleGroup(const std::string& name, const std::vector<DataType*>& dataTypes, int keyCode)
    : name_(name), dataList_(dataTypes), keyCode_(keyCode) {}

CycleGroup::CycleGroup(const std::string& name, DataType* dt, int keyCode)
    : name_(name), keyCode_(keyCode) {
    if (dt) dataList_.push_back(dt);
}

void CycleGroup::addDataType(DataType* dt) {
    if (dt == nullptr) return;
    if (!exists(dt)) dataList_.push_back(dt);
}

void CycleGroup::addFirst(DataType* dt) {
    if (dt == nullptr) return;
    if (!exists(dt)) dataList_.insert(dataList_.begin(), dt);
}

void CycleGroup::removeDataType(DataType* dt) {
    for (auto it = dataList_.begin(); it != dataList_.end(); ++it) {
        if (*it == dt || (*it && dt && (*it)->isEquivalent(dt))) {
            dataList_.erase(it);
            return;
        }
    }
}

void CycleGroup::removeFirst() {
    if (!dataList_.empty()) dataList_.erase(dataList_.begin());
}

void CycleGroup::removeLast() {
    if (!dataList_.empty()) dataList_.pop_back();
}

bool CycleGroup::contains(DataType* dt) const {
    return exists(dt);
}

bool CycleGroup::exists(DataType* dt) const {
    for (auto* d : dataList_) {
        if (d && dt && d->isEquivalent(dt)) return true;
    }
    return false;
}

DataType* CycleGroup::getNextDataType(DataType* currentDataType, bool stackPointers) {
    if (dataList_.empty()) return nullptr;

    DataType* dataType = currentDataType;

    if (stackPointers && dynamic_cast<Pointer*>(dataType)) {
        auto* ptr = dynamic_cast<Pointer*>(dataType);
        DataType* nextBase = getNextDataType(ptr->getDataType(), true);
        return ptr->newPointer(nextBase);
    }

    int index = -1;
    if (dataType != nullptr) {
        for (size_t i = 0; i < dataList_.size(); i++) {
            DataType* cycleDt = dataList_[i];
            if (cycleDt && dataType->isEquivalent(cycleDt)) {
                index = static_cast<int>(i);
                break;
            }
        }
    }

    if (++index >= static_cast<int>(dataList_.size())) {
        dataType = dataList_[0];
    } else {
        dataType = dataList_[index];
    }

    return dataType;
}

CycleGroup* CycleGroup::getByteCycleGroup() {
    static CycleGroup* g = nullptr;
    if (g == nullptr) {
        g = new CycleGroup("Cycle: byte,word,dword,qword");
        g->addDataType(new ByteDataType());
        g->addDataType(new WordDataType());
        g->addDataType(new DWordDataType());
        g->addDataType(new QWordDataType());
    }
    return g;
}

CycleGroup* CycleGroup::getFloatCycleGroup() {
    static CycleGroup* g = nullptr;
    if (g == nullptr) {
        g = new CycleGroup("Cycle: float,double,longdouble");
        g->addDataType(new FloatDataType());
        g->addDataType(new DoubleDataType());
        g->addDataType(new LongDoubleDataType());
    }
    return g;
}

CycleGroup* CycleGroup::getStringCycleGroup() {
    static CycleGroup* g = nullptr;
    if (g == nullptr) {
        g = new CycleGroup("Cycle: char,string,unicode");
        g->addDataType(new CharDataType());
        g->addDataType(new StringDataType());
        g->addDataType(new UnicodeDataType());
    }
    return g;
}

const std::vector<CycleGroup*>& CycleGroup::getAllCycleGroups() {
    static std::vector<CycleGroup*> all = {
        getByteCycleGroup(),
        getFloatCycleGroup(),
        getStringCycleGroup()
    };
    return all;
}

} // namespace ghidra
