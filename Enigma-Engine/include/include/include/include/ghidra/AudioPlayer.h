#pragma once

#include <string>
#include "ghidra/Playable.h"

namespace ghidra {

class AudioPlayer : public Playable {
public:
    AudioPlayer() = default;

    void play() override {}
    std::string getName() const { return "AudioPlayer"; }
};

} // namespace ghidra
