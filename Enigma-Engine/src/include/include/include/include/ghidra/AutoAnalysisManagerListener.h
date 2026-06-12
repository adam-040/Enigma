#pragma once

namespace ghidra {

class AutoAnalysisManager;

class AutoAnalysisManagerListener {
public:
    virtual ~AutoAnalysisManagerListener() = default;
    virtual void analysisEnded(AutoAnalysisManager* manager, bool isCancelled) = 0;
};

} // namespace ghidra
