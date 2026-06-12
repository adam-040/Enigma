/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

namespace ghidra {

enum class Side { LEFT, RIGHT };

template<typename T>
class Duo {
public:
    Duo() = default;
    Duo(T a, T b) : first_(a), second_(b) {}

    T get(Side side) const { return side == Side::LEFT ? first_ : second_; }

private:
    T first_{};
    T second_{};
};

} // namespace ghidra
