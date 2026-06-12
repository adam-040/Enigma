#include "ghidra/BitmapResource.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/MemoryAccessException.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace ghidra {

BitmapResource::BitmapResource(MemBuffer* buf) {
    parseHeader(buf);
}

void BitmapResource::parseHeader(MemBuffer* buf) {
    size_ = buf->getInt(0);
    width_ = buf->getInt(4);
    height_ = buf->getInt(8);
    planes_ = buf->getShort(12);
    bitCount_ = buf->getShort(14);
    compression_ = buf->getInt(16);
    sizeImage_ = buf->getInt(20);
    xPelsPerMeter_ = buf->getInt(24);
    yPelsPerMeter_ = buf->getInt(28);
    clrUsed_ = buf->getInt(32);
    clrImportant_ = buf->getInt(36);
    imageDataOffset_ = size_ + getColorMapLength();

    if (bitCount_ < 0 || width_ < 0 || height_ < 0 || bitCount_ > 32 || width_ > 4096 || height_ > 4096) {
        throw std::runtime_error("Invalid dimensions for bitmap");
    }

    int computedClrUsed = getClrUsed();
    if (computedClrUsed > 0x10000) {
        throw std::runtime_error("Invalid colormap dimensions for bitmap");
    }
}

int BitmapResource::getClrUsed() const {
    if (clrUsed_ == 0 && bitCount_ > 0 && bitCount_ <= 32) {
        return static_cast<int>(std::pow(2.0, bitCount_));
    }
    return clrUsed_;
}

int BitmapResource::getImageDataSize() const {
    if (sizeImage_ == 0) {
        return getComputedUncompressedImageDataSize();
    }
    return sizeImage_;
}

int BitmapResource::getColorMapLength() const {
    if (bitCount_ == 32 || bitCount_ == 24) {
        return 0;
    }
    return getClrUsed() * 4;
}

int BitmapResource::getComputedUncompressedImageDataSize() const {
    return getBytesPerLine() * getHeight();
}

int BitmapResource::getBytesPerLine() const {
    int lineLen = getWidth() * getBitCount();
    if (getBitCount() == 1) {
        lineLen = lineLen / 8;
    } else if (getBitCount() == 4) {
        lineLen = (lineLen + 4) / 8;
    } else if (getBitCount() == 24) {
        lineLen = lineLen / 8;
    } else {
        lineLen = lineLen / 8;
    }
    if ((lineLen % 4) != 0) {
        lineLen = lineLen + (4 - (lineLen % 4));
    }
    return lineLen;
}

std::vector<uint8_t> BitmapResource::getPixelData(MemBuffer* buf) const {
    std::vector<uint8_t> rawPixels(getImageDataSize());
    buf->getBytes(rawPixels.data(), static_cast<int>(rawPixels.size()), size_ + getColorMapLength());
    return rawPixels;
}

} // namespace ghidra
