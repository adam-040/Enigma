#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class AddressTableAnalyzer : public AbstractAnalyzer {
public:
    AddressTableAnalyzer();
    ~AddressTableAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    bool processAddressTable(Program* program, const Address& start, TaskMonitor* monitor);

    int minimumTableSize_ = -1;
    int tableAlignment_ = 4;
    int ptrAlignment_ = 1;
    bool autoLabelTable_ = false;
    bool createBookmarksEnabled_ = true;
    long minPointerAddress_ = 0x1024;
    long maxPointerDistance_ = 0xffffff;
    bool relocationGuideEnabled_ = true;
    bool allowOffcutReferences_ = false;
};

} // namespace ghidra
