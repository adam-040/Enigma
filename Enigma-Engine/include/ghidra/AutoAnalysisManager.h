#pragma once

#include <ghidra/Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/AnalysisTaskList.h>
#include <ghidra/AutoAnalysisManagerListener.h>
#include <ghidra/MessageLog.h>
#include <vector>
#include <memory>
#include <map>
#include <string>

namespace ghidra {

class AnalysisScheduler;

class AutoAnalysisManager {
public:
    explicit AutoAnalysisManager(Program* program);
    ~AutoAnalysisManager();

    Program* getProgram() const { return program_; }
    MessageLog& getMessageLog() { return log_; }

    // Analyzer registration
    void registerAnalyzer(std::unique_ptr<Analyzer> analyzer);
    void initializeDefaultAnalyzers();
    Analyzer* getAnalyzer(const std::string& name) const;

    // Collect all registered analyzers (for backward compat / inspection)
    std::vector<Analyzer*> getAnalyzers() const;
    AnalysisTaskList* getTaskList(AnalyzerType type);

    // Analysis entry points
    void analyze(TaskMonitor* monitor);
    void analyzeRange(const AddressSetView& set, TaskMonitor* monitor);
    void analyzeOne(Analyzer* analyzer, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log);

    // Ghidra-compatible analysis lifecycle
    void startAnalysis(TaskMonitor* monitor);
    void startAnalysis(TaskMonitor* monitor, bool printTimes);
    void scheduleOneTimeAnalysis(Analyzer* analyzer, const AddressSetView& set);
    void waitForAnalysis(int timeoutMs, TaskMonitor* monitor);
    void reAnalyzeAll(const AddressSetView& set);
    void cancelQueuedTasks();
    void setIgnoreChanges(bool ignore);
    bool isAnalyzing() const { return isAnalyzing_; }

    // Event-driven change notifications
    void blockAdded(const AddressSetView& set);
    void codeDefined(const AddressSetView& set);
    void codeDefined(const Address& addr);
    void dataDefined(const AddressSetView& set);
    void functionDefined(const AddressSetView& set);
    void functionDefined(const Address& addr);
    void functionModifierChanged(const AddressSetView& set);
    void functionModifierChanged(const Address& addr);
    void functionSignatureChanged(const AddressSetView& set);
    void functionSignatureChanged(const Address& addr);
    void externalAdded(const Address& addr);

    // Scheduling
    void scheduleTask(AnalysisScheduler* scheduler);

    // Listener management
    void addListener(AutoAnalysisManagerListener* listener);
    void removeListener(AutoAnalysisManagerListener* listener);

    // Options
    void registerOptions();
    void initializeOptions();

    // Static utilities
    static AutoAnalysisManager* getAnalysisManager(Program* program);
    static bool hasAutoAnalysisManager(Program* program);

    void dispose();

private:
    Program* program_;
    MessageLog log_;
    bool isAnalyzing_ = false;
    bool ignoreChanges_ = false;

    AnalysisTaskList byteTasks_;
    AnalysisTaskList instructionTasks_;
    AnalysisTaskList functionTasks_;
    AnalysisTaskList functionModifierTasks_;
    AnalysisTaskList functionSignatureTasks_;
    AnalysisTaskList dataTasks_;
    AnalysisTaskList* taskArray_[6];

    std::vector<AutoAnalysisManagerListener*> listeners_;
    std::vector<AnalysisScheduler*> pendingSchedulers_;

    // Static manager map (Program → AutoAnalysisManager)
    static std::map<Program*, AutoAnalysisManager*>& getManagerMap();

    AddressSet buildFullAddressSet();
    void notifyAnalysisEnded(bool isCancelled);
    void addToTaskList(std::unique_ptr<Analyzer> analyzer);
    void processSchedulerQueue();
};

} // namespace ghidra
