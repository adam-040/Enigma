#include <ghidra/FlowOverride.h>

namespace ghidra {

std::string flowOverrideToString(FlowOverride fo) {
    switch (fo) {
        case FlowOverride::BRANCH:
            return "branch";
        case FlowOverride::CALL:
            return "call";
        case FlowOverride::CALL_RETURN:
            return "callreturn";
        case FlowOverride::RETURN:
            return "return";
        default:
            return "none";
    }
}

FlowOverride stringToFlowOverride(const std::string& name) {
    if (name == "branch") {
        return FlowOverride::BRANCH;
    } else if (name == "call") {
        return FlowOverride::CALL;
    } else if (name == "callreturn") {
        return FlowOverride::CALL_RETURN;
    } else if (name == "return") {
        return FlowOverride::RETURN;
    }
    return FlowOverride::NONE;
}

} // namespace ghidra
