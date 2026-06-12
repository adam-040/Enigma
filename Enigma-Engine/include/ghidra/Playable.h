#pragma once

namespace ghidra {

class Playable {
public:
    virtual ~Playable() = default;
    virtual void play() = 0;
};

} // namespace ghidra
