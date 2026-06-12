#include <ghidra/ContextSetting.h>

namespace ghidra {

ContextSetting::ContextSetting(Register* reg, uint64_t value,
                               const Address& startAddr, const Address& endAddr)
    : register_(reg), value_(value), startAddr_(startAddr), endAddr_(endAddr) {}

void ContextSetting::encode(Encoder& encoder) {
    encoder.openElement(ELEM_SET);
    encoder.writeString(ATTRIB_NAME, register_->getName());
    encoder.writeString(ATTRIB_VAL, std::to_string(value_));
    encoder.closeElement(ELEM_SET);
}

bool ContextSetting::isEquivalent(const ContextSetting& obj) const {
    return startAddr_ == obj.startAddr_ &&
           endAddr_ == obj.endAddr_ &&
           register_->getName() == obj.register_->getName() &&
           value_ == obj.value_;
}

uint64_t ContextSetting::parseBigInteger(const std::string& valStr, uint64_t defaultValue) {
    std::string s = valStr;
    int radix = 10;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
        radix = 16;
    }
    try {
        return std::stoull(s, nullptr, radix);
    } catch (...) {
        return defaultValue;
    }
}

void ContextSetting::parseContextSet(std::vector<ContextSetting>&,
                                      XmlPullParser*, CompilerSpec*) {}

void ContextSetting::parseContextData(std::vector<ContextSetting>&,
                                       XmlPullParser*, CompilerSpec*) {}

void ContextSetting::encodeContextData(Encoder&,
                                        const std::vector<ContextSetting>&) {}

} // namespace ghidra
