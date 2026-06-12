#include "ghidra/IconResource.h"
#include "ghidra/MemBuffer.h"

namespace ghidra {

IconResource::IconResource(MemBuffer* buf)
    : BitmapResource(buf) {}

int IconResource::getHeight() const {
    return height_ / 2;
}

int IconResource::getImageDataSize() const {
    return getComputedUncompressedImageDataSize();
}

int IconResource::getMaskLength() {
    int lineLen = ((((getWidth() + 7) / 8) + 3) / 4) * 4;
    return lineLen * getHeight();
}

} // namespace ghidra
