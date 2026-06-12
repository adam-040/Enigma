#include "ghidra/BitmapResourceDataType.h"
#include "ghidra/BitmapResource.h"
#include "ghidra/DataTypeComponent.h"
#include "ghidra/ReadOnlyDataTypeComponent.h"
#include "ghidra/DWordDataType.h"
#include "ghidra/WordDataType.h"
#include "ghidra/ByteDataType.h"
#include "ghidra/ArrayDataType.h"
#include <typeinfo>

namespace ghidra {

BitmapResourceDataType::BitmapResourceDataType()
    : BitmapResourceDataType(nullptr) {}

BitmapResourceDataType::BitmapResourceDataType(DataTypeManager* dtm)
    : BitmapResourceDataType(CategoryPath(), "BitmapResource", dtm) {}

BitmapResourceDataType::BitmapResourceDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm)
    : DynamicDataType(path, name, dtm) {}

std::string BitmapResourceDataType::getDescription() const {
    return "Bitmap stored as a Resource";
}

std::string BitmapResourceDataType::getMnemonic(Settings* settings) const {
    return "BitmapRes";
}

std::string BitmapResourceDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<Bitmap-Image>";
}

const std::type_info& BitmapResourceDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* BitmapResourceDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<BitmapResourceDataType*>(this);
    }
    return new BitmapResourceDataType(dtm);
}

std::vector<DataTypeComponent*> BitmapResourceDataType::getAllComponents(MemBuffer* buf) {
    std::vector<DataTypeComponent*> comps;
    BitmapResource* bmr = getBitmapResource(buf);
    if (!bmr) {
        return comps;
    }
    addComponents(buf, bmr, comps);
    delete bmr;
    return comps;
}

int BitmapResourceDataType::addComp(DataType* dataType, int length, const std::string& fieldName,
                                     std::vector<DataTypeComponent*>& comps, int offset) {
    comps.push_back(new ReadOnlyDataTypeComponent(dataType, this, length, comps.size(), offset, fieldName, nullptr));
    return offset + length;
}

int BitmapResourceDataType::addComp(DataType* dataType, int length, const std::string& fieldName,
                                     std::vector<DataTypeComponent*>& comps, int offset, MemBuffer* buf) {
    return addComp(dataType, length, fieldName, comps, offset);
}

BitmapResource* BitmapResourceDataType::getBitmapResource(MemBuffer* buf) {
    try {
        return new BitmapResource(buf);
    } catch (...) {
        return nullptr;
    }
}

int BitmapResourceDataType::addComponents(MemBuffer* buf, BitmapResource* bmr,
                                           std::vector<DataTypeComponent*>& comps) {
    int offset = 0;
    offset = addComp(&DWordDataType::dataType(), 4, "size", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "width", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "height", comps, offset);
    offset = addComp(&WordDataType::dataType(), 2, "planes", comps, offset);
    offset = addComp(&WordDataType::dataType(), 2, "bitCount", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "compression", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "sizeImage", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "XpelsPerMeter", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "YpelsPerMeter", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "clrUsed", comps, offset);
    offset = addComp(&DWordDataType::dataType(), 4, "clrImportant", comps, offset);

    int arraySize = bmr->getColorMapLength();
    if (arraySize > 0) {
        ArrayDataType array(&ByteDataType::dataType(), arraySize, 1);
        offset = addComp(&array, arraySize, "ColorMap", comps, offset);
    }
    arraySize = bmr->getRawSizeImage();
    if (arraySize > 0) {
        ArrayDataType array(&ByteDataType::dataType(), arraySize, 1);
        offset = addComp(&array, arraySize, "ImageData", comps, offset);
    }
    return offset;
}

} // namespace ghidra
