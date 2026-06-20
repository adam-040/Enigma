#pragma once

#include <cstdint>

class CutterSeekable
{
public:
    virtual ~CutterSeekable() = default;
    virtual void seek(uint64_t addr) = 0;
    virtual uint64_t currentAddress() const = 0;
    virtual void setSyncState(bool synced) = 0;
    virtual bool syncState() const = 0;
};
