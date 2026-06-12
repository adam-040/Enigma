/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/PrimitiveExtractor.h>
#include <ghidra/TypeDef.h>
#include <ghidra/Array.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/Composite.h>
#include <ghidra/DataTypeComponent.h>

namespace ghidra {

int PrimitiveExtractor::checkOverlap(std::vector<Primitive>& res, std::vector<Primitive>& small,
                                      int point, Primitive& big) {
    int endOff = big.offset + big.dt->getAlignedLength();
    bool useSmall = Metatype::getMetatype(big.dt) == Metatype::TYPE_FLOAT;
    while (point < (int)small.size()) {
        int curOff = small[point].offset;
        if (curOff >= endOff) break;
        curOff += small[point].dt->getAlignedLength();
        if (curOff > endOff) return -1;
        if (useSmall) res.push_back(small[point]);
        point += 1;
    }
    if (!useSmall) res.push_back(big);
    return point;
}

bool PrimitiveExtractor::commonRefinement(std::vector<Primitive>& first, std::vector<Primitive>& second) {
    int firstPoint = 0;
    int secondPoint = 0;
    std::vector<Primitive> common;
    while (firstPoint < (int)first.size() && secondPoint < (int)second.size()) {
        Primitive& firstElement = first[firstPoint];
        Primitive& secondElement = second[secondPoint];
        if (firstElement.offset < secondElement.offset &&
            firstElement.offset + firstElement.dt->getAlignedLength() <= secondElement.offset) {
            common.push_back(firstElement);
            firstPoint += 1;
            continue;
        }
        if (secondElement.offset < firstElement.offset &&
            secondElement.offset + secondElement.dt->getAlignedLength() <= firstElement.offset) {
            common.push_back(secondElement);
            secondPoint += 1;
            continue;
        }
        if (firstElement.dt->getAlignedLength() >= secondElement.dt->getAlignedLength()) {
            secondPoint = checkOverlap(common, second, secondPoint, firstElement);
            if (secondPoint < 0) return false;
            firstPoint += 1;
        } else {
            firstPoint = checkOverlap(common, first, firstPoint, secondElement);
            if (firstPoint < 0) return false;
            secondPoint += 1;
        }
    }
    while (firstPoint < (int)first.size()) {
        common.push_back(first[firstPoint]);
        firstPoint += 1;
    }
    while (secondPoint < (int)second.size()) {
        common.push_back(second[secondPoint]);
        secondPoint += 1;
    }
    first.clear();
    first.insert(first.end(), common.begin(), common.end());
    return true;
}

bool PrimitiveExtractor::handleUnion(Union* dt, int max, int offset) {
    if (flags_ & FLAG_UNION_INVALID) return false;
    int num = dt->getNumComponents();
    if (num == 0) return false;
    DataTypeComponent* curField = dt->getComponent(0);
    PrimitiveExtractor common(curField->getDataType(), false, offset + curField->getOffset(), max);
    if (!common.valid_) return false;
    for (int i = 1; i < num; ++i) {
        curField = dt->getComponent(i);
        PrimitiveExtractor next(curField->getDataType(), false, offset + curField->getOffset(), max);
        if (!next.valid_) return false;
        if (!commonRefinement(common.primitives, next.primitives)) return false;
    }
    if ((int)primitives.size() + (int)common.primitives.size() > max) return false;
    for (int i = 0; i < (int)common.primitives.size(); ++i) {
        primitives.push_back(common.primitives[i]);
    }
    return true;
}

bool PrimitiveExtractor::extract(DataType* dt, int max, int offset) {
    if (auto* td = dynamic_cast<TypeDef*>(dt)) {
        dt = td->getBaseDataType();
    }
    int metaType = Metatype::getMetatype(dt);
    switch (metaType) {
        case Metatype::TYPE_UNKNOWN:
            flags_ |= FLAG_UNKNOWN;
            // fall-thru
        case Metatype::TYPE_INT:
        case Metatype::TYPE_UINT:
        case Metatype::TYPE_BOOL:
        case Metatype::TYPE_CODE:
        case Metatype::TYPE_FLOAT:
        case Metatype::TYPE_PTR:
        case Metatype::TYPE_PTRREL:
            if ((int)primitives.size() >= max) return false;
            primitives.push_back(Primitive(dt, offset));
            return true;
        case Metatype::TYPE_ARRAY: {
            Array* arr = dynamic_cast<Array*>(dt);
            if (!arr) return false;
            int numEls = arr->getNumElements();
            DataType* base = arr->getDataType();
            for (int i = 0; i < numEls; ++i) {
                if (!extract(base, max, offset)) return false;
                offset += base->getAlignedLength();
            }
            return true;
        }
        case Metatype::TYPE_UNION:
            return handleUnion(dynamic_cast<Union*>(dt), max, offset);
        case Metatype::TYPE_STRUCT:
            break;
        default:
            return false;
    }
    Structure* structPtr = dynamic_cast<Structure*>(dt);
    if (!structPtr) return false;
    bool isPacked = structPtr->isPackingEnabled();
    std::vector<DataTypeComponent*> components = structPtr->getDefinedComponents();
    int expectedOff = offset;
    for (auto* component : components) {
        DataType* compDT = component->getDataType();
        int curOff = component->getOffset() + offset;
        if (!isPacked) {
            int align = compDT->getAlignment();
            if (curOff % align != 0) flags_ |= FLAG_UNALIGNED;
            int rem = expectedOff % align;
            if (rem != 0) expectedOff += (align - rem);
            if (expectedOff != curOff) flags_ |= FLAG_EXTRA_SPACE;
        }
        if (!extract(compDT, max, curOff)) return false;
        expectedOff = curOff + compDT->getAlignedLength();
    }
    return true;
}

PrimitiveExtractor::PrimitiveExtractor(DataType* dt, bool unionIllegal, int offset, int max) {
    valid_ = true;
    flags_ = 0;
    if (unionIllegal) flags_ |= FLAG_UNION_INVALID;
    if (!extract(dt, max, offset)) {
        valid_ = false;
    }
}

} // namespace ghidra
