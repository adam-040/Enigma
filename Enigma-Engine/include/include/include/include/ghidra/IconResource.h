#pragma once

#include <string>
#include "ghidra/BitmapResource.h"

namespace ghidra {

class MemBuffer;

class IconResource : public BitmapResource {
public:
    explicit IconResource(MemBuffer* buf);

    int getHeight() const override;
    int getImageDataSize() const override;
    int getMaskLength() override;
};

} // namespace ghidra
