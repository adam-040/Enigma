#pragma once

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace ghidra {

class ColorIcon {
public:
    explicit ColorIcon(int rgb) : rgbColor_(rgb) {}

    int getRGB() const { return rgbColor_; }

    std::string toString() const {
        std::stringstream ss;
        ss << "#" << std::hex << std::uppercase << std::setfill('0') << std::setw(6)
           << (rgbColor_ & 0xFFFFFF);
        return ss.str();
    }

private:
    int rgbColor_;
};

} // namespace ghidra
