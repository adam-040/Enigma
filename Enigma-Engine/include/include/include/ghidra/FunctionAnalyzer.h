#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <string>

namespace ghidra {

class Function;
class Listing;
class Reference;

class FunctionAnalyzer : public AbstractAnalyzer {
protected:
    static constexpr int NOTIFICATION_INTERVAL = 256;
    bool createOnlyThunks_ = false;
    std::string analysisMessage_ = "Find Function Starts : ";

public:
    FunctionAnalyzer();
    ~FunctionAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

protected:
    bool isThunkFunction(Program* program, const Address& entry) const;
    bool isPlaceHolderFunctionThatShouldBeFixed(Program* program, class Listing* listing, class Function* func) const;
    bool fallthroughCall(Program* program, Reference* ref) const;
};

} // namespace ghidra
