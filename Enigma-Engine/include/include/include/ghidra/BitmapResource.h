#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace ghidra {

class MemBuffer;
class IOException;

class BitmapResource {
public:
    static constexpr int BOTTOM_UP = 1;

    explicit BitmapResource(MemBuffer* buf);

    int getSize() const { return size_; }
    int getWidth() const { return width_; }
    virtual int getHeight() const { return height_; }
    int getPlanes() const { return planes_; }
    int getBitCount() const { return bitCount_; }
    int getCompression() const { return compression_; }
    int getXPelsPerMeter() const { return xPelsPerMeter_; }
    int getYPelsPerMeter() const { return yPelsPerMeter_; }
    int getClrUsed() const;
    int getClrImportant() const { return clrImportant_; }
    int getSizeImage() const { return sizeImage_; }
    int getRawSizeImage() const { return rawSizeImage_; }
    virtual int getImageDataSize() const;
    int getColorMapLength() const;
    virtual int getMaskLength() { return 0; }

    std::vector<uint8_t> getPixelData(MemBuffer* buf) const;

protected:
    int size_ = 0;
    int width_ = 0;
    int height_ = 0;
    int planes_ = 0;
    int bitCount_ = 0;
    int compression_ = 0;
    int xPelsPerMeter_ = 0;
    int yPelsPerMeter_ = 0;
    int clrUsed_ = 0;
    int clrImportant_ = 0;
    int sizeImage_ = 0;
    int rawSizeImage_ = -1;
    int imageDataOffset_ = 0;
    int rowOrder_ = BOTTOM_UP;

    int getComputedUncompressedImageDataSize() const;
    int getBytesPerLine() const;

    void parseHeader(MemBuffer* buf);
};

} // namespace ghidra
