#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

struct FunctionEvidence {
    uint64_t address;
    int score;
    std::vector<std::string> evidence;
    std::string classification;
    int instrCount;
    std::string firstMnemonic;
    std::string lastMnemonic;
    uint64_t nearestEnigmaDist;
};

class AggressiveRecoveryAnalyzer : public AbstractAnalyzer {
    bool createBookmarksEnabled_ = true;
    int maxOrphanCandidates_ = 500;
    int confidenceThreshold_ = 10;

    // Scoring weights
    static constexpr int SCORE_PDATA_ENTRY = 100;
    static constexpr int SCORE_EXPORT_TABLE = 100;
    static constexpr int SCORE_IMPORT_THUNK = 90;
    static constexpr int SCORE_MULTIPLE_CALL_REFS = 80;
    static constexpr int SCORE_RDATA_8BYTE_PTR = 75;
    static constexpr int SCORE_SINGLE_CALL_REF = 60;
    static constexpr int SCORE_4BYTE_RVA_RDATA = 50;
    static constexpr int SCORE_VTABLE_RUN = 70;
    static constexpr int SCORE_VALID_RET_ENDING = 30;
    static constexpr int SCORE_VALID_INT3_ENDING = 25;
    static constexpr int SCORE_VALID_JMP_ENDING = 20;
    static constexpr int SCORE_EXECUTABLE_BYTES_ONLY = 10;
    static constexpr int SCORE_PENALTY_OVERLAP = -50;
    static constexpr int SCORE_PENALTY_TRUNCATION = -30;

    int scoreCandidate(uint64_t addr, int instrCount,
                       const std::string& lastMnemonic,
                       bool hasCallRefs, bool hasDataRefs,
                       bool inPdata, bool inExport,
                       bool inVtableRun, uint64_t nearestDist);

public:
    AggressiveRecoveryAnalyzer();

    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;

    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

    // Exposed for testing
    int classifyScore(int total) const;
    std::string classifyLevel(int total) const;

private:
    int scanOrphanIslands(Program* program, Memory* memory, Listing* listing,
                          FunctionManager* funcMgr, TaskMonitor* monitor,
                          std::vector<FunctionEvidence>& candidates);

    int scanGapCallTargets(Program* program, Memory* memory, Listing* listing,
                           FunctionManager* funcMgr, TaskMonitor* monitor,
                           std::vector<FunctionEvidence>& candidates);

    int scanTinyHelpers(Program* program, Memory* memory, Listing* listing,
                        FunctionManager* funcMgr, TaskMonitor* monitor,
                        std::vector<FunctionEvidence>& candidates);
};

} // namespace ghidra
