#pragma once

#include <string>

namespace ghidra {

/**
 * FlowOverride defines the type of control flow modification
 * applied to a specific instruction.
 * Matches ghidra.program.model.listing.FlowOverride
 */
enum class FlowOverride {
    NONE = 0,
    BRANCH = 1,
    CALL = 2,
    CALL_RETURN = 3,
    RETURN = 4
};

std::string flowOverrideToString(FlowOverride fo);
FlowOverride stringToFlowOverride(const std::string& name);

} // namespace ghidra
