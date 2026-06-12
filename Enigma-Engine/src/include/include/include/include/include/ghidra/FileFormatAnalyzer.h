#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <string>

namespace ghidra {

class Program;
class Address;
class AddressSetView;
class DataType;
class Data;
class ProgramFragment;
class TaskMonitor;
class MessageLog;

class FileFormatAnalyzer : public AbstractAnalyzer {
public:
    FileFormatAnalyzer(const std::string& name, const std::string& description,
                       AnalyzerType type = AnalyzerType::BYTE_ANALYZER);
    virtual ~FileFormatAnalyzer() = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override final;

    virtual bool analyze(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) = 0;

protected:
    Address toAddr(Program* program, uint64_t offset);
    Data* createData(Program* program, const Address& address, DataType* datatype);
    ProgramFragment* createFragment(Program* program, const std::string& fragmentName,
                                    const Address& start, const Address& end);
    void removeEmptyFragments(Program* program);
    void changeDataSettings(Program* program, TaskMonitor* monitor);
    void changeFormatToString(Data* data);
    Data* getDataAt(Program* program, const Address& address);
    Data* getDataAfter(Program* program, const Address& address);
    bool setPlateComment(Program* program, const Address& address, const std::string& comment);
};

} // namespace ghidra
