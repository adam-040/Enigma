#pragma once

#include <ghidra/PrintLanguage.h>
#include <string>

namespace ghidra {

class Funcdata;
class HighFunction;
class VarnodeAST;
class PcodeOpAST;
class HighVariable;
class DataType;

class PrintC : public PrintLanguage {
public:
    PrintC();
    ~PrintC() override = default;

    void reset() override;
    void printFuncdata(Funcdata& fd) override;
    void printHighFunction(HighFunction& hf) override;

    void printOp(PcodeOpAST* op) override;
    void printVarnode(VarnodeAST* vn) override;
    void printVariable(HighVariable* hi) override;
    void printDataType(DataType* type) override;

    void printConstant(uintb val, int4 size) override;
    void printAddress(const Address& addr) override;
    void printComment(const std::string& text) override;

    void emitFunctionHeader(const std::string& name, const std::string& returnType);
    void emitFunctionFooter();
    void emitAssignment(const std::string& dest, const std::string& src);
    void emitDeclaration(const std::string& type, const std::string& name);
    void emitReturn(const std::string& value);

    std::string formatConstant(uintb val, int4 size) const;
    std::string getOpMnemonic(int opcode) const;
    std::string getDataTypeName(DataType* type) const;
};

} // namespace ghidra
