#pragma once

#include <string>
#include "ghidra/Playable.h"

namespace ghidra {

class ScorePlayer : public Playable {
public:
    ScorePlayer() = default;

    void play() override {}
    std::string getName() const { return "ScorePlayer"; }
};

} // namespace ghidra
