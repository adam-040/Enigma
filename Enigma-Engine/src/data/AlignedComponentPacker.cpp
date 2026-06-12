/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AlignedComponentPacker.h>
#include <ghidra/InternalDataTypeComponent.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/CompositeAlignmentHelper.h>
#include <ghidra/Undefined1DataType.h>
#include <stdexcept>

namespace ghidra {

AlignedComponentPacker::AlignedComponentPacker(int packValue, DataOrganization* dataOrganization)
    : dataOrganization_(dataOrganization),
      packValue_(packValue) {
    bitFieldPacking_ = dataOrganization->getBitFieldPacking();
}

void AlignedComponentPacker::addComponent(InternalDataTypeComponent* dtc, bool isLastComponent) {
    if (!packComponent(dtc)) {
        initGroup(dtc, isLastComponent);
    }
    lastComponent_ = dtc;
    ++nextOrdinal_;
    defaultAlignment_ = getComponentAlignmentLCM(defaultAlignment_);
}

bool AlignedComponentPacker::componentsChanged() const {
    return componentsChanged_;
}

int AlignedComponentPacker::getDefaultAlignment() const {
    return defaultAlignment_;
}

int AlignedComponentPacker::getLength() const {
    if (lastComponent_ == nullptr) {
        return 0;
    }
    int offset = 0;
    if (groupOffset_ >= 0 && lastComponent_->isBitFieldComponent() &&
        bitFieldPacking_->useMSConvention()) {
        auto* lastBitFieldDt = dynamic_cast<BitFieldDataType*>(lastComponent_->getDataType());
        if (lastBitFieldDt) {
            offset = groupOffset_ + lastBitFieldDt->getBaseTypeSize();
        } else {
            offset = lastComponent_->getOffset() + lastComponent_->getLength();
        }
    } else {
        offset = lastComponent_->getOffset() + lastComponent_->getLength();
        if (!bitFieldPacking_->useMSConvention() && lastComponent_->isZeroBitFieldComponent()) {
            auto* bitfieldDt = dynamic_cast<BitFieldDataType*>(lastComponent_->getDataType());
            if (bitfieldDt) {
                int sizeAlignment = bitfieldDt->getBaseDataType()->getAlignment();
                getBitFieldAlignment(bitfieldDt);
                offset = DataOrganizationImpl::getAlignedOffset(sizeAlignment, offset);
            }
        }
    }
    return offset;
}

bool AlignedComponentPacker::packComponent(InternalDataTypeComponent* dataTypeComponent) {
    if (lastComponent_ == nullptr || dataTypeComponent->isZeroBitFieldComponent()) {
        return false;
    }

    if (dataTypeComponent->isBitFieldComponent()) {
        if (!lastComponent_->isZeroBitFieldComponent() && bitFieldPacking_->useMSConvention()) {
            if (!lastComponent_->isBitFieldComponent()) {
                return false;
            }
            if (getBitFieldTypeSize(dataTypeComponent) != getBitFieldTypeSize(lastComponent_)) {
                return false;
            }
        }
        alignAndPackBitField(dataTypeComponent);
        return true;
    }

    if (!lastComponent_->isZeroBitFieldComponent() && bitFieldPacking_->useMSConvention()) {
        return false;
    }

    int offset;
    if (lastComponent_->isZeroBitFieldComponent()) {
        offset = groupOffset_;
    } else {
        offset = lastComponent_->getOffset() + lastComponent_->getLength();
    }

    alignAndPackNonBitfieldComponent(dataTypeComponent, offset);
    return true;
}

void AlignedComponentPacker::initGroup(InternalDataTypeComponent* dataTypeComponent, bool isLastComponent) {
    groupOffset_ = getLength();
    lastAlignment_ = 1;

    if (dataTypeComponent->isBitFieldComponent()) {
        auto* zeroBitFieldDt = dynamic_cast<BitFieldDataType*>(dataTypeComponent->getDataType());
        if (!zeroBitFieldDt) return;

        if (dataTypeComponent->isZeroBitFieldComponent()) {
            int alignment = getZeroBitFieldAlignment(zeroBitFieldDt, isLastComponent);

            int zeroBitOffset = dataOrganization_->isBigEndian() ? 7 : 0;
            if (zeroBitFieldDt->getBitOffset() != zeroBitOffset ||
                zeroBitFieldDt->getStorageSize() != 1) {
                // Would need to repack bitfield — mark as changed
                componentsChanged_ = true;
            }

            if (isLastComponent) {
                int offset = DataOrganizationImpl::getAlignedOffset(
                    zeroBitFieldDt->getBaseDataType()->getAlignment(), groupOffset_);
                updateComponent(dataTypeComponent, nextOrdinal_, offset, 0,
                                alignment > 0 ? alignment : 1);
                groupOffset_ = -1;
            } else {
                zeroAlignment_ = alignment;
                if (bitFieldPacking_->useMSConvention()) {
                    lastAlignment_ = alignment;
                }
            }
        } else {
            lastComponent_ = nullptr;
            alignAndPackBitField(dataTypeComponent);
        }
    } else {
        lastComponent_ = nullptr;
        alignAndPackNonBitfieldComponent(dataTypeComponent, groupOffset_);
    }
}

void AlignedComponentPacker::alignAndPackNonBitfieldComponent(
        InternalDataTypeComponent* dataTypeComponent, int minOffset) {
    DataType* componentDt = dataTypeComponent->getDataType();

    int dtSize = componentDt->isZeroLength() ? 0 : componentDt->getAlignedLength();
    if (dtSize < 0) {
        dtSize = dataTypeComponent->getLength();
    }

    int alignment = CompositeAlignmentHelper::getPackedAlignment(
        componentDt->getAlignment(), packValue_);

    int offset;
    if (lastComponent_ != nullptr && lastComponent_->isZeroBitFieldComponent()) {
        adjustZeroLengthBitField(nextOrdinal_ - 1, alignment);
        offset = groupOffset_;
    } else {
        offset = DataOrganizationImpl::getAlignedOffset(alignment, minOffset);
        if (lastComponent_ == nullptr) {
            groupOffset_ = offset;
        }
    }

    updateComponent(dataTypeComponent, nextOrdinal_, offset, dtSize, alignment);
}

void AlignedComponentPacker::alignAndPackBitField(InternalDataTypeComponent* dataTypeComponent) {
    auto* bitfieldDt = dynamic_cast<BitFieldDataType*>(dataTypeComponent->getDataType());
    if (!bitfieldDt) return;

    if (lastComponent_ != nullptr && lastComponent_->isZeroBitFieldComponent()) {
        int alignment = bitFieldPacking_->useMSConvention()
            ? getBitFieldAlignment(bitfieldDt) : zeroAlignment_;
        adjustZeroLengthBitField(nextOrdinal_ - 1, alignment);
    }

    int offset;
    int bitsConsumed;

    int alignment = CompositeAlignmentHelper::getPackedAlignment(
        bitfieldDt->getBaseDataType()->getAlignment(), packValue_);
    lastAlignment_ = std::max(alignment, lastAlignment_);

    if (lastComponent_ == nullptr) {
        offset = DataOrganizationImpl::getAlignedOffset(alignment, groupOffset_);
        bitsConsumed = 0;
        groupOffset_ = offset;
    } else if (lastComponent_->isZeroBitFieldComponent()) {
        offset = groupOffset_;
        bitsConsumed = 0;
    } else {
        alignment = getBitFieldAlignment(bitfieldDt);

        BitFieldDataType* lastBitfieldDt = nullptr;
        if (lastComponent_->isBitFieldComponent()) {
            lastBitfieldDt = dynamic_cast<BitFieldDataType*>(lastComponent_->getDataType());
            offset = lastComponent_->getEndOffset();
            if (dataOrganization_->isBigEndian()) {
                bitsConsumed = 8 - lastBitfieldDt->getBitOffset();
            } else {
                bitsConsumed = (lastBitfieldDt->getBitSize() + lastBitfieldDt->getBitOffset()) % 8;
            }
            if (bitsConsumed == 8 || bitsConsumed == 0) {
                bitsConsumed = 0;
                ++offset;
            }
        } else {
            offset = lastComponent_->getOffset() + lastComponent_->getLength();
            bitsConsumed = 0;
        }

        int byteSize = (bitfieldDt->getBitSize() + bitsConsumed + 7) / 8;
        int endOffset = offset + byteSize - 1;

        if (offset % alignment != 0 || byteSize > bitfieldDt->getBaseTypeSize()) {
            int alignedBaseOffset =
                DataOrganizationImpl::getAlignedOffset(alignment, offset) - alignment;
            if (endOffset >= alignedBaseOffset + bitfieldDt->getBaseTypeSize()) {
                offset = DataOrganizationImpl::getAlignedOffset(alignment, offset + 1);
                endOffset = offset + byteSize - 1;
                bitsConsumed = 0;
            }
        }

        if (groupOffset_ >= 0 && lastBitfieldDt != nullptr &&
            endOffset >= (groupOffset_ + lastBitfieldDt->getBaseTypeSize())) {
            groupOffset_ = bitFieldPacking_->useMSConvention() ? offset : -1;
        }
    }

    int byteSize = setBitFieldDataType(dataTypeComponent, bitfieldDt, bitsConsumed);
    updateComponent(dataTypeComponent, nextOrdinal_, offset, byteSize, alignment);
}

int AlignedComponentPacker::setBitFieldDataType(InternalDataTypeComponent* dataTypeComponent,
        BitFieldDataType* currentBitFieldDt, int bitsConsumed) {
    int byteSize = (currentBitFieldDt->getBitSize() + bitsConsumed + 7) / 8;
    int bitOffset;
    if (dataOrganization_->isBigEndian()) {
        bitOffset = (byteSize * 8) - currentBitFieldDt->getBitSize() - bitsConsumed;
    } else {
        bitOffset = bitsConsumed;
    }

    if (bitOffset != currentBitFieldDt->getBitOffset()) {
        componentsChanged_ = true;
    }
    return byteSize;
}

void AlignedComponentPacker::updateComponent(InternalDataTypeComponent* dataTypeComponent,
        int ordinal, int offset, int length, int alignment) {
    if (ordinal != dataTypeComponent->getOrdinal() ||
        offset != dataTypeComponent->getOffset() ||
        length != dataTypeComponent->getLength()) {
        dataTypeComponent->update(ordinal, offset, length);
        componentsChanged_ = true;
    }
    lastAlignment_ = std::max(lastAlignment_, alignment);
}

int AlignedComponentPacker::getComponentAlignmentLCM(int allComponentsLCM) {
    if (lastAlignment_ == 0) return lastAlignment_;

    int alignment = lastAlignment_;
    if (packValue_ > 0 && alignment > packValue_) {
        alignment = packValue_;
    }
    return DataOrganizationImpl::getLeastCommonMultiple(allComponentsLCM, alignment);
}

int AlignedComponentPacker::getBitFieldTypeSize(InternalDataTypeComponent* dataTypeComponent) {
    auto* componentDt = dynamic_cast<BitFieldDataType*>(dataTypeComponent->getDataType());
    if (componentDt) {
        return componentDt->getBaseTypeSize();
    }
    throw std::runtime_error("expected bitfield component only");
}

int AlignedComponentPacker::getBitFieldAlignment(BitFieldDataType* bitfieldDt) const {
    if (!bitFieldPacking_->useMSConvention() && packValue_ != CompositeInternal::DEFAULT_PACKING) {
        return 1;
    }
    return CompositeAlignmentHelper::getPackedAlignment(
        bitfieldDt->getBaseDataType()->getAlignment(), packValue_);
}

bool AlignedComponentPacker::isIgnoredZeroBitField(BitFieldDataType* zeroBitFieldDt) {
    if (!zeroBitFieldDt->isZeroLength()) return false;
    if (bitFieldPacking_->useMSConvention()) {
        return lastComponent_ == nullptr || !lastComponent_->isBitFieldComponent();
    }
    return false;
}

int AlignedComponentPacker::getZeroBitFieldAlignment(BitFieldDataType* zeroBitFieldDt, bool isLastComponent) {
    if (isIgnoredZeroBitField(zeroBitFieldDt)) {
        return -1;
    }

    if (!bitFieldPacking_->isTypeAlignmentEnabled()) {
        int zeroLengthBoundary = bitFieldPacking_->getZeroLengthBoundary();
        if (zeroLengthBoundary > 0) return zeroLengthBoundary;
        return 1;
    }

    int pack = packValue_;
    if (!bitFieldPacking_->useMSConvention() && !isLastComponent) {
        pack = CompositeInternal::NO_PACKING;
    }

    return CompositeAlignmentHelper::getPackedAlignment(
        zeroBitFieldDt->getBaseDataType()->getAlignment(), pack);
}

void AlignedComponentPacker::adjustZeroLengthBitField(int ordinal, int minimumAlignment) {
    int minOffset = DataOrganizationImpl::getAlignedOffset(minimumAlignment, groupOffset_);
    int zeroAlignmentOffset = DataOrganizationImpl::getAlignedOffset(zeroAlignment_, groupOffset_);

    if (minOffset >= zeroAlignmentOffset) {
        groupOffset_ = minOffset;
    } else {
        groupOffset_ = zeroAlignmentOffset;
    }

    updateComponent(lastComponent_, ordinal, groupOffset_, 0, minimumAlignment);
}

} // namespace ghidra
